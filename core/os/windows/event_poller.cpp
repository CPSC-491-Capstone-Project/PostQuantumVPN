#include "event_poller.hpp"
#include "logger.hpp"

#include <winsock2.h>

#include <atomic>
#include <utility>
#include <string>
#include <cstring>

/*
    Windows EventPoller implementation using WSAPoll.
    Since Windows has no epoll-style fd, poller_handle_ is a synthetic
    counter value (any non-negative int) that is non-kInvalidHandle when open.
    The registered socket list is stored in native_events_ as a packed array
    of WSAPOLLFD structs.
*/

using core::utils::Logger;

static std::atomic<std::int32_t> g_poller_counter{0};

static WSAPOLLFD* PollFds(std::vector<std::byte>& buf) {
    return reinterpret_cast<WSAPOLLFD*>(buf.data());
}

static std::size_t PollFdCount(const std::vector<std::byte>& buf) {
    return buf.size() / sizeof(WSAPOLLFD);
}

static SHORT ToWSA(std::uint32_t mask) {
    SHORT ev = 0;
    if (mask & core::network::EventMask::Readable) ev |= POLLRDNORM;
    if (mask & core::network::EventMask::Writable) ev |= POLLWRNORM;
    if (mask & core::network::EventMask::Error)    ev |= POLLERR;
    if (mask & core::network::EventMask::Hangup)   ev |= POLLHUP;
    return ev;
}

static std::uint32_t FromWSA(SHORT revents) {
    std::uint32_t mask = 0;
    if (revents & POLLRDNORM) mask |= core::network::EventMask::Readable;
    if (revents & POLLWRNORM) mask |= core::network::EventMask::Writable;
    if (revents & POLLERR)    mask |= core::network::EventMask::Error;
    if (revents & POLLHUP)    mask |= core::network::EventMask::Hangup;
    return mask;
}

namespace core::network {

    EventPoller::~EventPoller() {
        Close();
    }

    EventPoller::EventPoller(EventPoller&& other) noexcept
        : poller_handle_{std::exchange(other.poller_handle_, kInvalidHandle)}
        , native_events_{std::move(other.native_events_)}
    {}

    EventPoller& EventPoller::operator=(EventPoller&& other) noexcept {
        if (this != &other) {
            Close();
            poller_handle_ = std::exchange(other.poller_handle_, kInvalidHandle);
            native_events_ = std::move(other.native_events_);
        }
        return *this;
    }

    bool EventPoller::Open() {
        if (IsOpen()) {
            Logger::Warning("EventPoller: Open called on already open poller");
            return false;
        }

        poller_handle_ = g_poller_counter.fetch_add(1);
        native_events_.clear();
        return true;
    }

    void EventPoller::Close() {
        if (IsOpen()) {
            native_events_.clear();
            poller_handle_ = kInvalidHandle;
        } else {
            Logger::Warning("EventPoller: Close called on closed poller");
        }
    }

    bool EventPoller::Add(Handle handle, std::uint32_t interest_mask) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Add called on closed poller");
            return false;
        }

        std::size_t count = PollFdCount(native_events_);
        WSAPOLLFD* fds = count ? PollFds(native_events_) : nullptr;
        for (std::size_t i = 0; i < count; ++i) {
            if (fds[i].fd == static_cast<SOCKET>(handle)) {
                Logger::Error("EventPoller: Add called for already-registered handle");
                return false;
            }
        }

        std::size_t old_size = native_events_.size();
        native_events_.resize(old_size + sizeof(WSAPOLLFD));
        auto* entry = reinterpret_cast<WSAPOLLFD*>(native_events_.data() + old_size);
        entry->fd      = static_cast<SOCKET>(handle);
        entry->events  = ToWSA(interest_mask);
        entry->revents = 0;
        return true;
    }

    bool EventPoller::Modify(Handle handle, std::uint32_t interest_mask) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Modify called on closed poller");
            return false;
        }

        std::size_t count = PollFdCount(native_events_);
        WSAPOLLFD* fds = count ? PollFds(native_events_) : nullptr;
        for (std::size_t i = 0; i < count; ++i) {
            if (fds[i].fd == static_cast<SOCKET>(handle)) {
                fds[i].events = ToWSA(interest_mask);
                return true;
            }
        }

        Logger::Error("EventPoller: Modify called for non-registered handle");
        return false;
    }

    bool EventPoller::Remove(Handle handle) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Remove called on closed poller");
            return false;
        }

        std::size_t count = PollFdCount(native_events_);
        WSAPOLLFD* fds = count ? PollFds(native_events_) : nullptr;
        for (std::size_t i = 0; i < count; ++i) {
            if (fds[i].fd == static_cast<SOCKET>(handle)) {
                if (i < count - 1) {
                    fds[i] = fds[count - 1];
                }
                native_events_.resize(native_events_.size() - sizeof(WSAPOLLFD));
                return true;
            }
        }

        Logger::Error("EventPoller: Remove called for non-registered handle");
        return false;
    }

    int EventPoller::Poll(std::span<PollEvent> out, int timeout_ms) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Poll called on closed poller");
            return -1;
        }

        if (out.empty()) {
            return 0;
        }

        std::size_t count = PollFdCount(native_events_);
        if (count == 0) {
            return 0;
        }

        WSAPOLLFD* fds = PollFds(native_events_);
        for (std::size_t i = 0; i < count; ++i) {
            fds[i].revents = 0;
        }

        int ready = WSAPoll(fds, static_cast<ULONG>(count), timeout_ms);
        if (ready == SOCKET_ERROR) {
            Logger::Error("EventPoller: WSAPoll failed: " + std::to_string(WSAGetLastError()));
            return -1;
        }

        int written = 0;
        for (std::size_t i = 0; i < count && written < static_cast<int>(out.size()); ++i) {
            if (fds[i].revents != 0) {
                out[written].handle = static_cast<Handle>(fds[i].fd);
                out[written].mask   = FromWSA(fds[i].revents);
                ++written;
            }
        }

        return written;
    }

} // namespace core::network
