/*
    Copyright (C) 2018 Google Inc.
    Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>
*/

import Mixin from './mixin';
import {REFRESH_PROPOSAL_DIFF} from '../../events/eventTypes';

export default Mixin({
  isProposable: true,
}, {
  after_update() {
    this.dispatch({
      ...REFRESH_PROPOSAL_DIFF,
    });
  },
});
