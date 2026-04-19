#include "event_poller.hpp"
#include "logger.hpp"

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <utility>
#include <string>

/*
    See
    https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html
    for kqueue reference.

    Key differences from Linux epoll:
    - kqueue fires one event *per filter* (EVFILT_READ, EVFILT_WRITE, …)
      whereas epoll fires one event per fd with a bitmask.
    - Poll() coalesces multiple kqueue events for the same fd into a
      single PollEvent so callers see the same interface as on Linux.
    - EV_EOF  maps to EventMask::Hangup  (remote end closed)
    - EV_ERROR maps to EventMask::Error  (kernel-reported error)
*/

using core::utils::Logger;

namespace core::network {

    // =============================================================================
    // Function Defs
    // =============================================================================
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

        poller_handle_ = static_cast<Handle>(::kqueue());
        if (poller_handle_ < 0) {
            Logger::Critical("EventPoller: Failed to create kqueue instance: " + std::string(std::strerror(errno)));
            poller_handle_ = kInvalidHandle;
            return false;
        }

        Logger::Info("EventPoller: Created kqueue instance " + HandleTag(poller_handle_));
        return true;
    }

    void EventPoller::Close() {
        if (IsOpen()) {
            Logger::Info("EventPoller: Closing kqueue instance " + HandleTag(poller_handle_));
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

        struct kevent changes[2];
        int n = 0;

        if (interest_mask & EventMask::Readable)
            EV_SET(&changes[n++], handle, EVFILT_READ,  EV_ADD | EV_ENABLE, 0, 0, nullptr);
        if (interest_mask & EventMask::Writable)
            EV_SET(&changes[n++], handle, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, nullptr);

        if (n > 0 && ::kevent(poller_handle_, changes, n, nullptr, 0, nullptr) < 0) {
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

        // For each filter, either enable or remove it.
        // Deleting a filter that was never registered returns ENOENT which we ignore.
        struct kevent changes[2];
        EV_SET(&changes[0], handle, EVFILT_READ,
               (interest_mask & EventMask::Readable) ? (EV_ADD | EV_ENABLE) : EV_DELETE,
               0, 0, nullptr);
        EV_SET(&changes[1], handle, EVFILT_WRITE,
               (interest_mask & EventMask::Writable) ? (EV_ADD | EV_ENABLE) : EV_DELETE,
               0, 0, nullptr);

        if (::kevent(poller_handle_, changes, 2, nullptr, 0, nullptr) < 0 && errno != ENOENT) {
            Logger::Error("EventPoller: Failed to modify " + HandleTag(handle) + ": " + std::string(std::strerror(errno)));
            return false;
        }

        return true;
    }

    bool EventPoller::Remove(Handle handle) {
        if (!IsOpen()) {
            Logger::Error("EventPoller: Remove called on closed poller");
            return false;
        }

        struct kevent changes[2];
        EV_SET(&changes[0], handle, EVFILT_READ,  EV_DELETE, 0, 0, nullptr);
        EV_SET(&changes[1], handle, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);

        // ENOENT means the filter was never registered — not an error for us.
        if (::kevent(poller_handle_, changes, 2, nullptr, 0, nullptr) < 0 && errno != ENOENT) {
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

        // Request up to out.size()*2 native events: each fd can produce a
        // separate read and write kevent, so we need double the slots to
        // avoid dropping events before coalescing.
        const std::size_t max_native    = out.size() * 2;
        const std::size_t required_bytes = max_native * sizeof(struct kevent);
        if (native_events_.size() < required_bytes) {
            native_events_.resize(required_bytes);
        }

        auto* events = reinterpret_cast<struct kevent*>(native_events_.data());

        struct timespec ts{};
        struct timespec* tsp = nullptr;
        if (timeout_ms >= 0) {
            ts.tv_sec  = timeout_ms / 1000;
            ts.tv_nsec = static_cast<long>(timeout_ms % 1000) * 1'000'000L;
            tsp = &ts;
        }

        int count = ::kevent(
            poller_handle_,
            nullptr, 0,
            events, static_cast<int>(max_native),
            tsp
        );

        if (count < 0) {
            // EINTR is not an error; a signal interrupted the wait.
            if (errno == EINTR) {
                Logger::Debug("EventPoller: kevent interrupted by signal");
                return 0;
            }
            Logger::Error("EventPoller: kevent failed: " + std::string(std::strerror(errno)));
            return -1;
        }

        // Coalesce kqueue events (one per filter) into PollEvents (one per fd).
        int out_count = 0;
        for (int i = 0; i < count; ++i) {
            const Handle h = static_cast<Handle>(events[i].ident);

            std::uint32_t mask = 0;
            if (events[i].filter == EVFILT_READ)  mask |= EventMask::Readable;
            if (events[i].filter == EVFILT_WRITE) mask |= EventMask::Writable;
            if (events[i].flags  & EV_ERROR)       mask |= EventMask::Error;
            if (events[i].flags  & EV_EOF)         mask |= EventMask::Hangup;

            // Merge into an existing slot for this handle, or open a new one.
            bool merged = false;
            for (int j = 0; j < out_count; ++j) {
                if (out[j].handle == h) {
                    out[j].mask |= mask;
                    merged = true;
                    break;
                }
            }

            if (!merged && out_count < static_cast<int>(out.size())) {
                out[out_count].handle = h;
                out[out_count].mask   = mask;
                ++out_count;
            }
        }

        return out_count;
    }

    // =============================================================================
    // Helpers
    // =============================================================================
    static std::string HandleTag(Handle h) {
        return "[handle:" + std::to_string(h) + "]";
    }

} // namespace core::network
