#ifndef _PQVPN_CORE_NETWORK_EVENT_POLLER_HPP_
#define _PQVPN_CORE_NETWORK_EVENT_POLLER_HPP_

#include <cstdint>
#include <span>
#include <vector>

namespace core::network {

    using Handle = std::int32_t;
    inline constexpr Handle kInvalidHandle = -1;

    // Event interest and result flags.
    // These map to EPOLL events on linux
    struct EventMask {
        static constexpr std::uint32_t Readable = 0x01;
        static constexpr std::uint32_t Writable = 0x02;
        static constexpr std::uint32_t Error = 0x04;
        static constexpr std::uint32_t Hangup = 0x08;
    };

    // Event returned by Poll().
    // Identifies which fd fired and what conditions triggered
    struct PollEvent {
        Handle handle{kInvalidEventHandle};
        std::uint32_t mask{0};

        [[nodiscard]] bool IsReadable() const { return mask & EventMask::Readable; }
        [[nodiscard]] bool IsWritable() const { return mask & EventMask::Writable; }
        [[nodiscard]] bool IsError() const { return mask & EventMask::Error; }
        [[nodiscard]] bool IsHangup() const { return mask & EventMask::Hangup; }
    };

    // Open() -> Add/Modify/Remove -> While in event loop Poll() -> Close()
    class EventPoller {
    public:
        EventPoller() = default;
        ~EventPoller();

        EventPoller(const EventPoller&) = delete;
        EventPoller& operator=(const EventPoller&) = delete;
        EventPoller(EventPoller&& other) noexcept;
        EventPoller& operator=(const EventPoller&& other) noexcept;

        bool Open();
        bool Close();
        bool Add(Handle handle, std::uint32_t interest_mask);
        bool Modify(Handle handle, std::uint32_t interest_mask);
        bool Remove(Handle handle);

        // Block until event fires or timeout expires
        //      timeout_ms < 0  : block forever
        //      timeout_ms == 0 : non-blocking poll
        // Returns the number of events written or -1 on error
        int Poll(std::span<PollEvent> out, int timout_ms);

        [[nodiscard]] bool IsOpen() const { return poller_handle_ != kInvalidHandle; }
        [[nodiscard]] Handle GetHandle() const { return poller_handle_; }
    private:
        Handle poller_handle_{kInvalidHandle};

        // Internal buffer for OS_native events.
        // Sized once on first Poll() call and reused to avoid 
        // per-call allocation. 
        // This is the epoll_event array on Linux, kevent array on MacOS, ect.
        std::vector<std::byte> native_events_;
    };

} // namespace core::network

#endif // _PQVPN_CORE_NETWORK_EVENT_POLLER_HPP_