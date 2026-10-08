// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|packets: Vec<Vec<u8>>| hexgate::fuzz::channels(&packets));
