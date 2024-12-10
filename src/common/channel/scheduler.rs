// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub struct ChannelConfiguration {
    pub weight_unreliable: u16,
    pub weights_unreliable_ordered: Vec<u16>,
    pub weights_reliable: Vec<u16>,
}

pub(crate) struct _Scheduler {}
