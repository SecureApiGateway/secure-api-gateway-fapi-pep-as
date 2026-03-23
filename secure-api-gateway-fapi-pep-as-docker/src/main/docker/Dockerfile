#
# Copyright © 2020-2026 Ping Identity Corporation (obst@forgerock.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM ${docker.openig-image}
# Switching back to forgerock user, app will run as this
USER forgerock
# Create dir where secrets can be mounted into
RUN mkdir /var/ig/secrets

# Copy all config files into the docker image.
COPY --chown=forgerock:root configuration/bin/import-pem-certs.sh /home/forgerock
COPY --chown=forgerock:root dependencies ${IG_INSTANCE_DIR}/extra
COPY --chown=forgerock:root configuration/scripts ${IG_INSTANCE_DIR}/scripts
COPY --chown=forgerock:root configuration/config ${IG_INSTANCE_DIR}/config