# -*- coding: utf-8 -*-
__version__ = "0.1"
__author__ = "Equipe73"

"""
Script para parse do arquivo de configuracao Citrix Netscaler ns.config.
Utilizado para o processo de migracao para os novos ADCs.

Definicoes das estrutura de configuracao que serão extraidas:
rserver: add server [server_name] [server_ip] -state [server_status]
               -comment [server_comment]

servicegroup: add serviceGroup [sg_name] [sg_type] -maxClient [maxClient]
               -cip [cip] [cipheader] -usip [usip] -useproxyport
               [useproxyport] -healthMonitor [healthMonitor] -cltTimeout
               [cltTimeout] -svrTimeout [svrTimeout]

LB Virtual Server: add lb vserver [lb_name] [lb_type] [lb_ip] [lb_port]
                   -persistenceType [persistenceType] -timeout
                   [persistenceTimeout] -lbMethod [lbMethod]
                   -backupLBMethod [backupLBMethod] -state [state]
                   -cookieName [cookieName] -cltTimeout [cltTimeout]

CS Virtual Server: add cs vserver [cs_name] [cs_type] [cs_ip] [cs_port]
                   -cltTimeout [cltTimeout]

CS Action: add cs action [action_name] -targetLBVserver [targetLBVserver]

CS Policy: add cs policy [policy_name] -rule [policy_rule] -action [policy_action]

Certificado: add ssl certKey [certKey] -cert [cert] -key [key]
             -expiryMonitor [expiryMonitor] -inform [certtype] [certhash]
             -encrypted -encryptmethod [encryptmethod]

Certificado Link: link ssl certKey [cert] [certca]

Bind LB VS: bind lb vserver [lb_name] [sg_name]

Bind CS VS: bind cs vserver [cs_name] -policyName [policy_name] -priority
            [policy_priority] -lbvserver [lbvserver_default]

Bind SG: bind serviceGroup [sg_name] [server_name] [server_port] -weight [weight]
         -monitorName [monitorname] -state [member_state]

Bind SSL VS: bind ssl vserver [lb_name] -certkeyName [certkeyName] -cipherName
             [cipherName]
"""
import json

# Definicao das contantes de identificacao da linha de configuracao
REAL_SERVER = "add server "
SERVICE_GROUP = "add serviceGroup "
LB_VS = "add lb vserver "
CS_VS = "add cs vserver "
CS_ACTION = "add cs action "
CS_POLICY = "add cs policy "
CERTIFICADO = "add ssl certKey "
CERT_LINK = "link ssl certKey"
BIND_LB_VS = "bind lb vserver "
BIND_CS_VS = "bind cs vserver "
BIND_SG = "bind serviceGroup "
BIND_SSL_VS = "bind ssl vserver "
CS_HEADER_FILE = (
    "provider;instancia;particao;name_service;"
    + "vip_content_switching;porta_vip;protocol_cs;lb_method;"
    + "persistencetype;persistency_timeout;cookie_lb;protocol_sg;"
    + "monitor_type;name_server;ip_server;portas_servers;member_state;"
    + "usar_client_ip;nome_certificado;maxclient;allow_empty_pool;"
    + "prioridade_policy_bind;name_default_lb_vs;controle_contexto;contexto;"
    + "rule_cs"
)
LB_HEADER_FILE = (
    "provider;instancia;particao;name_service;"
    + "vip_load_balancing;porta_vip;protocol_vs;lb_method;persistencetype;"
    + "persistency_timeout;cookie_lb;protocol_sg;monitor_type;name_server;"
    + "ip_server;portas_servers;member_state;usar_client_ip;nome_certificado;"
    + "maxclient;allow_empty_pool"
)

# Definicao das variaveis de manipulacao
real_servers = dict()
service_group = dict()
lb_vserver = dict()
cs_vserver = dict()
cs_action = dict()
cs_policy = dict()
ssl_certkey = dict()
link_certKey = dict()
lb_bind = dict()
cs_bind = dict()
sg_bind = dict()

# Definicao das variaveis auxiliares
sg_name_controle = ""
server_list = list()

# Definicao das funcoes de tratamento do arquivo nsconfig
def definekeyid(configline: list, parameter: str) -> int:
    keyid = configline.index(parameter) if configline.__contains__(parameter) else 0
    return keyid


def returnkey(configline: list, keyid: int, index: int, defaultvalue="ENABLED") -> str:
    key = configline[keyid + index] if keyid else defaultvalue
    return key


def rserver(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(REAL_SERVER):
            server_state_id = definekeyid(linha.split(), "-state")
            server_state = returnkey(linha.split(), server_state_id, 1)
            server_name = linha.split()[2]
            server_ip = linha.split()[3]
            server_commet_id = definekeyid(linha.split(), "-comment")
            server_commet = returnkey(linha.split(), server_commet_id, 1, "")
            real_servers.update(
                {
                    server_name: {
                        "ip": server_ip,
                        "state": server_state,
                        "comment": server_commet,
                    }
                }
            )
    return real_servers


def servicegroup(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(SERVICE_GROUP):
            sg_name = linha.split()[2]
            sg_type = linha.split()[3]
            maxclient_id = definekeyid(linha.split(), "-maxClient")
            maxclient = returnkey(linha.split(), maxclient_id, 1, "")
            cip_id = definekeyid(linha.split(), "-cip")
            cip = returnkey(linha.split(), cip_id, 1, "DISABLED")
            if cip == "ENABLED":
                cipheader = returnkey(linha.split(), cip_id, 2, "")
            else:
                cipheader = ""
            usip_id = definekeyid(linha.split(), "-usip")
            usip = returnkey(linha.split(), usip_id, 1, "NO")
            useproxyport_id = definekeyid(linha.split(), "-useproxyport")
            useproxyport = returnkey(linha.split(), useproxyport_id, 1, "YES")
            healthmonitor_id = definekeyid(linha.split(), "-healthMonitor")
            healthmonitor = returnkey(linha.split(), healthmonitor_id, 1, "YES")
            clttimeout_id = definekeyid(linha.split(), "-cltTimeout")
            clttimeout = returnkey(linha.split(), clttimeout_id, 1, "180")
            svrtimeout_id = definekeyid(linha.split(), "-svrTimeout")
            svrtimeout = returnkey(linha.split(), svrtimeout_id, 1, "180")
            service_group.update(
                {
                    sg_name: {
                        "sg_type": sg_type,
                        "maxClient": maxclient,
                        "cip": cip,
                        "cipheader": cipheader,
                        "usip": usip,
                        "useproxyport": useproxyport,
                        "healthMonitor": healthmonitor,
                        "cltTimeout": clttimeout,
                        "svrTimeout": svrtimeout,
                    }
                }
            )
    return service_group


def lbvserver(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(LB_VS):
            lb_name = linha.split()[3]
            lb_type = linha.split()[4]
            lb_ip = linha.split()[5]
            lb_port = linha.split()[6]
            persistencetype_id = definekeyid(linha.split(), "-persistenceType")
            persistencetype = returnkey(linha.split(), persistencetype_id, 1, "NONE")
            persistencetimeout_id = definekeyid(linha.split(), "-timeout")
            persistencetimeout = returnkey(linha.split(), persistencetimeout_id, 1, "0")
            lbmethod_id = definekeyid(linha.split(), "-lbMethod")
            lbmethod = returnkey(linha.split(), lbmethod_id, 1, "ROUNDROBIN")
            backuplbmethod_id = definekeyid(linha.split(), "-backupLBMethod")
            backuplbmethod = returnkey(
                linha.split(), backuplbmethod_id, 1, "LEASTCONNECTION"
            )
            state_id = definekeyid(linha.split(), "-state")
            state = returnkey(linha.split(), state_id, 1, "ENABLED")
            cookiename_id = definekeyid(linha.split(), "-cookieName")
            cookiename = returnkey(linha.split(), cookiename_id, 1, "")
            rule_id = definekeyid(linha.split(), "-rule")
            rule = returnkey(linha.split(), rule_id, 1, "")
            clttimeout_id = definekeyid(linha.split(), "-cltTimeout")
            clttimeout = returnkey(linha.split(), clttimeout_id, 1, "180")
            lb_vserver.update(
                {
                    lb_name: {
                        "lb_type": lb_type,
                        "lb_ip": lb_ip,
                        "lb_port": lb_port,
                        "persistenceType": persistencetype,
                        "persistenceTimeout": persistencetimeout,
                        "lbMethod": lbmethod,
                        "backupLBMethod": backuplbmethod,
                        "state": state,
                        "cookieName": cookiename,
                        "cltTimeout": clttimeout,
                        "rule": rule,
                    }
                }
            )
    return lb_vserver


def csvserver(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(CS_VS):
            cs_name = linha.split()[3]
            cs_type = linha.split()[4]
            cs_ip = linha.split()[5]
            cs_port = linha.split()[6]
            clttimeout_id = definekeyid(linha.split(), "-cltTimeout")
            clttimeout = returnkey(linha.split(), clttimeout_id, 1, "180")
            cs_vserver.update(
                {
                    cs_name: {
                        "cs_type": cs_type,
                        "cs_ip": cs_ip,
                        "cs_port": cs_port,
                        "cltTimeout": clttimeout,
                    }
                }
            )
    return cs_vserver


def csaction(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(CS_ACTION):
            action_name = linha.split()[3]
            targetlbvserver_id = definekeyid(linha.split(), "-targetLBVserver")
            targetlbvserver = returnkey(
                linha.split(), targetlbvserver_id, 1, "NAO_DEFINIDO"
            )
            cs_action.update({action_name: {"targetLBVserver": targetlbvserver}})
    return cs_action


def cspolicy(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(CS_POLICY):
            policy_name = linha.split()[3]
            policy_rule_id = definekeyid(linha.split(), "-rule")
            policy_rule = returnkey(linha.split(), policy_rule_id, 1, "NAO_DEFINIDO")
            policy_action_id = definekeyid(linha.split(), "-action")
            policy_action = returnkey(
                linha.split(), policy_action_id, 1, "NAO_DEFINIDO"
            )
            cs_policy.update(
                {
                    policy_name: {
                        "policy_rule": policy_rule,
                        "policy_action": policy_action,
                    }
                }
            )
    return cs_policy


def sslcertkey(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(CERTIFICADO):
            certkey = linha.split()[3]
            cert_id = definekeyid(linha.split(), "-cert")
            cert = returnkey(linha.split(), cert_id, 1, "")
            key_id = definekeyid(linha.split(), "-key")
            key = returnkey(linha.split(), key_id, 1, "")
            expirymonitor_id = definekeyid(linha.split(), "-expiryMonitor")
            expirymonitor = returnkey(linha.split(), expirymonitor_id, 1, "ENABLED")
            ssl_certkey.update(
                {
                    certkey: {
                        "certificado": cert,
                        "key": key,
                        "expiryMonitor": expirymonitor,
                    }
                }
            )
    return ssl_certkey


def linkcertkey(configfile: list) -> dict:
    for linha in configfile:
        if linha.startswith(CERT_LINK):
            cert = linha.split()[3]
            certca = linha.split()[4]
            link_certKey.update({cert: {"CA_Cert": certca}})
    return link_certKey


def bindlbvs(configfile: list) -> dict:
    policyname = ""
    priority = ""
    gotopriorityexpression = ""
    typepolicy = ""
    for linha in configfile:
        if linha.startswith(BIND_LB_VS):
            if not linha.__contains__("-policyName"):
                lb_name = linha.split()[3]
                sg_name = linha.split()[4]
            else:
                lb_name = linha.split()[3]
                sg_name = lb_bind.get(lb_name)["ServGroup"]
                policyname_id = definekeyid(linha.split(), "-policyName")
                policyname = returnkey(linha.split(), policyname_id, 1, "")
                priority_id = definekeyid(linha.split(), "-priority")
                priority = returnkey(linha.split(), priority_id, 1, "")
                gotopriorityexpression_id = definekeyid(
                    linha.split(), "-gotoPriorityExpression"
                )
                gotopriorityexpression = returnkey(
                    linha.split(), gotopriorityexpression_id, 1, ""
                )
                typepolicy_id = definekeyid(linha.split(), "-type")
                typepolicy = returnkey(linha.split(), typepolicy_id, 1, "")
            lb_bind.update(
                {
                    lb_name: {
                        "ServGroup": sg_name,
                        "policyName": policyname,
                        "priority": priority,
                        "gotoPriorityExpression": gotopriorityexpression,
                        "type": typepolicy,
                    }
                }
            )
    return lb_bind


def bindcsvs(configfile: list) -> dict:
    cs_name_controle = ""
    for linha in configfile:
        if linha.startswith(BIND_CS_VS):
            cs_name = linha.split()[3]
            policyname_id = definekeyid(linha.split(), "-policyName")
            policyname = returnkey(linha.split(), policyname_id, 1, "")
            priority_id = definekeyid(linha.split(), "-priority")
            priority = returnkey(linha.split(), priority_id, 1, "")
            lbvserver_id = definekeyid(linha.split(), "-lbvserver")
            lbvserver = returnkey(linha.split(), lbvserver_id, 1, "")
            if cs_name != cs_name_controle:
                bindcsvs_list = list()
                bindcsvs_list.append([policyname, priority])
                cs_name_controle = cs_name
            elif not linha.__contains__("-lbvserver"):
                bindcsvs_list.append([policyname, priority])
            cs_bind.update({cs_name: {"lbvserver": lbvserver, "policy": bindcsvs_list}})
    return cs_bind


def bindsg(configfile: list) -> dict:
    sg_name_controle = ""
    for linha in configfile:
        if linha.startswith(BIND_SG):
            if not linha.__contains__("-monitorName"):
                sg_name = linha.split()[2]
                rserver_name = linha.split()[3]
                rserver_port = linha.split()[4]
                rserver_state_id = definekeyid(linha.split(), "-state")
                rserver_state = returnkey(linha.split(), rserver_state_id, 1, "ENABLED")
                rserver_weight_id = definekeyid(linha.split(), "-weight")
                rserver_weight = returnkey(linha.split(), rserver_weight_id, 1, "")
                sg_monitorname = "tcp"
            else:
                sg_monitorname_id = definekeyid(linha.split(), "-monitorName")
                sg_monitorname = returnkey(linha.split(), sg_monitorname_id, 1, "tcp")
            if sg_name != sg_name_controle:
                server_list = list()
                server_list.append(
                    [rserver_name, rserver_port, rserver_state, rserver_weight]
                )
                sg_name_controle = sg_name
            elif not linha.__contains__("-monitorName"):
                server_list.append(
                    [rserver_name, rserver_port, rserver_state, rserver_weight]
                )
            sg_bind.update(
                {sg_name: {"server_list": server_list, "monitor": sg_monitorname}}
            )
    return sg_bind


if __name__ == "__main__":
    with open("nsrunning.conf", "r", encoding="utf-8") as configfile:
        configuracoes = configfile.readlines()

    debuga = True
    result = bindcsvs(configuracoes)
    if debuga:
        with open("bindcsvs.json", "w") as df:
            json.dump(result, df)
