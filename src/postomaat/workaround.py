# -*- coding: utf-8 -*-
#   Copyright 2012-2018 Oli Schacher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#
#work around bug http://bugs.python.org/issue14452
#http://serverfault.com/questions/407643/rsyslog-update-on-amazon-linux-suddenly-treats-info-level-messages-as-emerg
import logging
class BOMLessFormatter(logging.Formatter):
    def format(self, record):
        return logging.Formatter.format(self, record).encode('utf-8')
