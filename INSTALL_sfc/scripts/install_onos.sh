cd; mkdir Downloads Applications
cd Downloads
wget -nc http://archive.apache.org/dist/karaf/3.0.5/apache-karaf-3.0.5.tar.gz
#wget -nc http://archive.apache.org/dist/maven/maven-3/3.3.9/binaries/apache-maven-3.3.9-bin.tar.gz
tar -zxvf apache-karaf-3.0.5.tar.gz -C ../Applications/
#tar -zxvf apache-maven-3.3.9-bin.tar.gz -C ../Applications/

sudo apt-get install software-properties-common -y
sudo add-apt-repository ppa:webupd8team/java -y
sudo apt-get update
sudo apt-get install oracle-java8-installer oracle-java8-set-default -y

sudo apt-get purge maven maven2 maven3
sudo apt-add-repository ppa:andrei-pozolotin/maven3
sudo apt-get update
sudo apt-get install maven3

cd; git clone https://gerrit.onosproject.org/onos

export JAVA_HOME=/usr/lib/jvm/java-8-oracle
# path to onos
export ONOS_ROOT=~/onos
source $ONOS_ROOT/tools/dev/bash_profile
# local IP
export ONOS_IP=192.168.178.44
export ONOS_APPS=drivers,openflow,proxyarp,mobility,fwd

cd onos
git checkout 1.6.0

mvn clean install
op
ok clean

