//! Sliding-window replay protection.
//!
//! Maintains a 256-packet window; any sequence number within the window that
//! has already been seen is rejected.

use hvpn_common::HvpnError;

const WINDOW_SIZE: u64 = 256;

/// Sliding 256-packet replay-protection window.
pub struct ReplayWindow {
    /// Highest sequence number received so far.
    highest: u64,
    /// Bitset of received sequence numbers within the window.
    /// Bit `i` corresponds to sequence number `highest - i`.
    window: u128,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            window: 0,
            initialized: false,
        }
    }

    /// Check `seq` and mark it as received if valid.
    ///
    /// Returns `Ok(())` on first-time receipt, `Err(ReplayDetected)` if the
    /// packet was already seen or falls outside the window behind us.
    pub fn check_and_advance(&mut self, seq: u64) -> Result<(), HvpnError> {
        if !self.initialized {
            self.highest = seq;
            self.window = 1;
            self.initialized = true;
            return Ok(());
        }

        if seq > self.highest {
            // New highest: slide the window.
            let shift = seq - self.highest;
            if shift >= 128 {
                self.window = 1;
            } else {
                self.window = (self.window << shift) | 1;
            }
            self.highest = seq;
        } else {
            let diff = self.highest - seq;
            if diff >= WINDOW_SIZE {
                return Err(HvpnError::ReplayDetected { seq });
            }
            let bit = 1u128 << diff;
            if self.window & bit != 0 {
                return Err(HvpnError::ReplayDetected { seq });
            }
            self.window |= bit;
        }
        Ok(())
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_accepted() {
        let mut rw = ReplayWindow::new();
        assert!(rw.check_and_advance(1).is_ok());
    }

    #[test]
    fn duplicate_rejected() {
        let mut rw = ReplayWindow::new();
        rw.check_and_advance(5).unwrap();
        assert!(rw.check_and_advance(5).is_err());
    }

    #[test]
    fn old_outside_window_rejected() {
        let mut rw = ReplayWindow::new();
        rw.check_and_advance(300).unwrap();
        // seq 0 is more than 256 behind 300 → outside window
        assert!(rw.check_and_advance(0).is_err());
    }

    #[test]
    fn in_order_sequence_accepted() {
        let mut rw = ReplayWindow::new();
        for i in 0..100u64 {
            assert!(rw.check_and_advance(i).is_ok());
        }
    }
}
