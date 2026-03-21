#include "event_poller.hpp"
#include "logger.hpp"

#include <sys/epoll.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <utility>
#include <string>

/*
    See
    https://man7.org/linux/man-pages/man7/epoll.7.html
    for epoll reference
*/

using core::utils::Logger;

namespace core::network {

    // =============================================================================
    // Function Defs
    // =============================================================================
    static std::uint32_t ToEpoll(std::uint32_t mask);
    static std::uint32_t FromEpoll(std::uint32_t ep);
    static std::string HandleTag(Handle h);

    // =============================================================================
    // Event Poller Implementation
    // =============================================================================
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
            Logger::Warning("EventPoller: Open called on already open poller " + HandleTag(poller_handle_));
            return false;
        }

        poller_handle_ = static_cast<Handle>(::epoll_create1(0));
        if (poller_handle_ < 0) {
            Logger::Critical("EventPoller: Failed to create epoll instance: " + std::string(std::strerror(errno)));
            poller_handle_ = kInvalidHandle;
            return false;
        }

        Logger::Info("EventPoller: Created epoll instance " + HandleTag(poller_handle_));
        return true;
    }

    void EventPoller::Close() {
        if (IsOpen()) {
            Logger::Info("EventPoller: Closing epoll instance " + HandleTag(poller_handle_));
            ::close(poller_handle_);
            poller_handle_ = kInvalidHandle;
            native_events_.clear();
        } else {
            Logger::Warning("EventPoller: Close called on closed poller");
        }
    }


    bool EventPoller::Add(Handle handle, std::uint32_t interest_mask) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Add called on closed poller");
            return false;
        }

        epoll_event ev{};
        ev.events  = ToEpoll(interest_mask);
        ev.data.fd = handle;

        if (::epoll_ctl(poller_handle_, EPOLL_CTL_ADD, handle, &ev) < 0) {
            Logger::Error("EventPoller: Failed to add " + HandleTag(handle) + ": " + std::string(std::strerror(errno)));
            return false;
        }

        Logger::Info("EventPoller: Added " + HandleTag(handle));
        return true;
    }

    bool EventPoller::Modify(Handle handle, std::uint32_t interest_mask) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Modify called on closed poller");
            return false;
        }

        epoll_event ev{};
        ev.events  = ToEpoll(interest_mask);
        ev.data.fd = handle;

        if (::epoll_ctl(poller_handle_, EPOLL_CTL_MOD, handle, &ev) < 0) {
            Logger::Error("EventPoller: Failed to modify " + HandleTag(handle)+ ": " + std::string(std::strerror(errno)));
            return false;
        }

        return true;
    }

    bool EventPoller::Remove(Handle handle) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Remove called on closed poller");
            return false;
        }

        if (::epoll_ctl(poller_handle_, EPOLL_CTL_DEL, handle, nullptr) < 0) {
            Logger::Error("EventPoller: Failed to remove " + HandleTag(handle) + ": " + std::string(std::strerror(errno)));
            return false;
        }

        Logger::Debug("EventPoller: Removed " + HandleTag(handle));
        return true;
    }

    int EventPoller::Poll(std::span<PollEvent> out, int timeout_ms) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Poll called on closed poller");
            return -1;
        }

        if (out.empty()) {
            return 0;
        }

        // Ensure our buffer can hold the requested number
        // of native events. This only reallocates if out.size() grew
        // since the last call.
        const std::size_t required_bytes = out.size() * sizeof(epoll_event);
        if (native_events_.size() < required_bytes) {
            native_events_.resize(required_bytes);
        }

        auto* events = reinterpret_cast<epoll_event*>(native_events_.data());

        int count = ::epoll_wait(
            poller_handle_,
            events,
            static_cast<int>(out.size()),
            timeout_ms
        );

        if (count < 0) {
            // EINTR is not an error; A signal interrupted the wait.
            // The caller can simply retry on the next loop iteration.
            if (errno == EINTR) {
                Logger::Debug("EventPoller: epoll_wait interrupted by signal");
                return 0;
            }

            Logger::Error("EventPoller: epoll_wait failed: " + std::string(std::strerror(errno)));
            return -1;
        }

        // Translate native events into our platform-neutral format
        for (auto i{0uz}; i < static_cast<std::size_t>(count); ++i) {
            out[i].handle = static_cast<Handle>(events[i].data.fd);
            out[i].mask   = FromEpoll(events[i].events);
        }

        return count;
    }

    // =============================================================================
    // Helpers
    // =============================================================================
    static std::uint32_t ToEpoll(std::uint32_t mask) {
        std::uint32_t ep = 0;
        if (mask & EventMask::Readable) ep |= EPOLLIN;
        if (mask & EventMask::Writable) ep |= EPOLLOUT;
        // EPOLLERR and EPOLLHUP are always delivered by the kernel
        // even if not requested, but we map them for completeness.
        if (mask & EventMask::Error)    ep |= EPOLLERR;
        if (mask & EventMask::Hangup)   ep |= EPOLLHUP;
        return ep;
    }

    static std::uint32_t FromEpoll(std::uint32_t ep) {
        std::uint32_t mask = 0;
        if (ep & EPOLLIN)  mask |= EventMask::Readable;
        if (ep & EPOLLOUT) mask |= EventMask::Writable;
        if (ep & EPOLLERR) mask |= EventMask::Error;
        if (ep & EPOLLHUP) mask |= EventMask::Hangup;
        return mask;
    }

    static std::string HandleTag(Handle h) {
        return "[handle:" + std::to_string(h) + "]";
    }




} // namespace core::network