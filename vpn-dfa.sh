#!/bin/bash
export HOST='170.80.5.237'
export FINGERPRINT='pin-sha256:B66Gb09/aS/Rm4BgKgYhflrbcHy0FKDec09EDbE2JLM='
export CONNECT_URL='https://vpn-dfa.jfsc.jus.br'
export RESOLVE='vpn-dfa.jfsc.jus.br:170.80.5.237'

eval 'openconnect --prot=gp  --authenticate https://vpn-dfa.jfsc.jus.br --script /etc/vpnc/vpnc-script';
[ -n $COOKIE ] && echo $COOKIE |   
sudo openconnect  --prot=gp --cookie-on-stdin ${HOST} --servercert ${FINGERPRINT} --resolve ${RESOLVE:+--resolve=$RESOLVE} --user=cev82 --cookieonly --script /etc/vpnc/vpnc-script --dump-http-traffic --verbose --background 


