#
# Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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

ARG base_image=gcr.io/forgerock-io/ig/docker-build:2025.6.0-latest-postcommit-fapi

FROM ${base_image}
# Switching back to forgerock user, app will run as this
USER forgerock
# Create dir where secrets can be mounted into
RUN mkdir /var/ig/secrets
COPY --chown=forgerock:root 7.3.0/ig/bin/import-pem-certs.sh /home/forgerock

# Copy all config files into the docker image.
COPY --chown=forgerock:root 7.3.0/ig/lib /opt/ig/lib
# Removing the bouncy castle jar that exists in the docker image as it clashes with the version used by SAPI-G.
# This version clash results in the JwkmsIssueCert.groovy script hanging
RUN rm -f /opt/ig/lib/bcprov-jdk18on-1.74.jar
COPY --chown=forgerock:root 7.3.0/ig/scripts /var/ig/scripts/
COPY --chown=forgerock:root 7.3.0/ig/config /var/ig/config/