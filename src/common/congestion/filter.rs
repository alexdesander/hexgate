// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::{Duration, Instant};

/// The minimum of the samples within a time window, in O(1) per sample: Kathleen
/// Nichols' three-sample filter, as in Linux `win_minmax` and BBR.
#[derive(Debug, Clone)]
pub struct Windowed<T> {
    samples: Option<[(Instant, T); 3]>,
    /// `better(a, b)`: `a` replaces `b` as the best sample.
    better: fn(&T, &T) -> bool,
}

impl<T: Copy + PartialOrd> Windowed<T> {
    pub fn min() -> Self {
        Self {
            samples: None,
            better: |a, b| a <= b,
        }
    }

    pub fn get(&self) -> Option<T> {
        self.samples.map(|samples| samples[0].1)
    }

    pub fn update(&mut self, now: Instant, value: T, window: Duration) -> T {
        let sample = (now, value);
        let Some(s) = &mut self.samples else {
            self.samples = Some([sample; 3]);
            return value;
        };
        if (self.better)(&value, &s[0].1) || now.saturating_duration_since(s[2].0) > window {
            *s = [sample; 3];
            return value;
        }
        if (self.better)(&value, &s[1].1) {
            s[1] = sample;
            s[2] = sample;
        } else if (self.better)(&value, &s[2].1) {
            s[2] = sample;
        }
        let age = now.saturating_duration_since(s[0].0);
        if age > window {
            s[0] = s[1];
            s[1] = s[2];
            s[2] = sample;
            if now.saturating_duration_since(s[0].0) > window {
                s[0] = s[1];
                s[1] = s[2];
            }
        } else if s[1].0 == s[0].0 && age > window / 4 {
            s[1] = sample;
            s[2] = sample;
        } else if s[2].0 == s[1].0 && age > window / 2 {
            s[2] = sample;
        }
        s[0].1
    }
}
