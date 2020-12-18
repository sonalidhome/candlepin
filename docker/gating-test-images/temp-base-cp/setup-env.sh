#!/bin/sh
#
# Builds a centos environment with all necessary dependencies to build candlepin
# based on the current candlepin version in stage. Useful postgresql client tools are also installed.
# This is used as a temp base image/layer for other candlepin images.

set -ve

export JAVA_VERSION=11
export JAVA_HOME=/usr/lib/jvm/java-$JAVA_VERSION

# Install & configure environment
yum install -y epel-release

PACKAGES=(
    findutils
    gcc
    gettext
    git
    hostname
    java-$JAVA_VERSION-openjdk-devel
    jss
    libxml2-python
    liquibase
    openssl
    postgresql-jdbc
    python-pip
    rsyslog
    ruby
    ruby-devel
    rubygem-bundler
    rubygem-json_pure
    rubygems
    tig
    tmux
    tomcat
    vim-enhanced
    wget
)

yum install -y ${PACKAGES[@]}

# Install postgres 9.5.X and the corresponding client tools (we need pg_dump)
yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-7-x86_64/pgdg-redhat-repo-latest.noarch.rpm
yum install -y yum install postgresql95 postgresql95-server

# pg_isready is used to check if the postgres server is up
# it is not included in the main postgresql package
# therefore we must build it
git clone https://github.com/postgres/postgres.git /root/postgres
cd /root/postgres
yum install -y bison bison-devel flex flex-devel readline-devel zlib-devel openssl-devel wget
./configure
# just builds the scripts folder, use installed postgres for everything else
make install src/bin/scripts/
# only need pg_isready for now
cp /usr/local/pgsql/bin/pg_isready /usr/local/bin/
# cleanup
cd /
rm -rf /root/postgres

# Setup for autoconf:
mkdir /etc/candlepin
echo "# AUTOGENERATED" > /etc/candlepin/candlepin.conf

cat > /root/.bashrc <<BASHRC
if [ -f /etc/bashrc ]; then
  . /etc/bashrc
fi

export HOME=/root
export JAVA_HOME=/usr/lib/jvm/java-$JAVA_VERSION
BASHRC

git clone https://github.com/candlepin/candlepin.git /candlepin
cd /candlepin

# Find out the candlepin version used in stage and switch to it:
curl -k https://subscription.rhsm.stage.redhat.com/subscription/status > stage_status.json
stage_version=$(python -c 'import json; fp = open("stage_status.json", "r"); obj = json.load(fp); fp.close(); print obj["version"]');
git checkout candlepin-${stage_version}-1
rm stage_status.json

./gradlew --no-daemon dependencies
