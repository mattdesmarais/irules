# Debug iRule 
#
# 

when CLIENT_ACCEPTED {
ACCESS::restrict_irule_events disable
# set a unique id for transaction
set uid [string range [AES::key 256] 15 23]

# set what's you want to retrieve 0 or 1
array set app_arrway_referer {
    client_dest_ip_port  0
    client_cert  0
    http_request 1
    http_request_release 0
    http_request_payload 0
    http_lb_selected 0
    http_response 1
    http_response_release 0
    http_response_payload 0
    http_time_process 0
    apm_access 1
    apm_access_internals 1 
}


if {$app_arrway_referer(client_dest_ip_port)} {
log local0. " ----------- client_dest_ip_port ----------- "
    clientside {
        log local0. "uid: $uid - Client IP Src: [IP::client_addr]:[TCP::client_port]"
    }
    log local0. "uid: $uid - Client IP Dest:[IP::local_addr]:[TCP::local_port]"
    log local0. " ----------- client_dest_ip_port ----------- "
    log local0. "  "
    }
}

when HTTP_REQUEST {

set http_request_time [clock clicks -milliseconds]

# Triggered when the system receives a certificate message from the client. The message may contain zero or more certificates.
if {$app_arrway_referer(client_cert)} {
log local0. " ----------- client_cert ----------- "
# SSL::cert count - Returns the total number of certificates that the peer has offered.
if {[SSL::cert count] > 0}{
# Check if there was no error in validating the client cert against LTM's server cert
if { [SSL::verify_result] == 0 }{
for {set i 0} {$i < [SSL::cert count]} {incr i}{
           log local0. "uid: $uid - cert number: $i"
           log local0. "uid: $uid - subject: [X509::subject [SSL::cert $i]]"
           log local0. "uid: $uid - Issuer Info: [X509::issuer [SSL::cert $i]]"
           log local0. "uid: $uid - cert serial: [X509::serial_number [SSL::cert $i]]"
}
} else {
# https://devcentral.f5.com/s/wiki/iRules.SSL__verify_result.ashx (OpenSSL verify result codes)
log local0. "uid: $uid - Cert Info: [X509::verify_cert_error_string [SSL::verify_result]]"
}
} else {
log local0. "uid: $uid - No client certificate provided"
}
log local0. " ----------- client_cert ----------- "
log local0. "  "
}

if {$app_arrway_referer(http_request)} {
log local0. " ----------- http_request ----------- "
if { [PROFILE::exists clientssl] == 1 } {
log local0. "uid: $uid - protocol: https"
log local0. "uid: $uid - cipher name: [SSL::cipher name]"
log local0. "uid: $uid - cipher version: [SSL::cipher version]"
}

log local0. "uid: $uid - VS Name: [virtual]"
log local0. "uid: $uid - Request: [HTTP::method] [HTTP::host][HTTP::uri]"

foreach aHeader [HTTP::header names] {
log local0. "uid: $uid - $aHeader: [HTTP::header value $aHeader]"
}
log local0. " ----------- http_request ----------- "
log local0. "  "
}

set collect_length_request [HTTP::header value "Content-Length"]
set contentlength 1

if {$app_arrway_referer(http_request_payload)} {
if { [catch {
if { $collect_length_request > 0 && $collect_length_request < 1048577 } {
set collect_length $collect_length_request
} else {
set collect_length 1048576
} 
if { $collect_length > 0 } {
HTTP::collect $collect_length_request
set contentlength 1
}
}] } {

# no DATA in POST Request
log local0. " ----------- http_request_payload ----------- "
log local0. "uid: $uid - Content-Length header null in request"
log local0. " ----------- http_request_payload ----------- "
log local0. " "
set contentlength 0
}
}
}

when HTTP_REQUEST_DATA {
if {$app_arrway_referer(http_request_payload)} {
log local0. " ----------- http_request_payload ----------- "
if {$contentlength} {
set postpayload [HTTP::payload]
log local0. "uid: $uid - post payload: $postpayload"
#HTTP::release
}
log local0. "  ----------- http_request_payload ----------- "
log local0. " "
}
}

when HTTP_REQUEST_RELEASE {

if {$app_arrway_referer(http_request_release)} {
log local0. "  ----------- http_request_release ----------- "
if { [PROFILE::exists clientssl] == 1 } {
log local0. "uid: $uid - cipher protocol: https"
log local0. "uid: $uid - cipher name: [SSL::cipher name]"
log local0. "uid: $uid - cipher version: [SSL::cipher version]"
}

log local0. "uid: $uid - VS Name: [virtual]"
log local0. "uid: $uid - Request: [HTTP::method] [HTTP::host][HTTP::uri]"

foreach aHeader [HTTP::header names] {
log local0. "uid: $uid - $aHeader: [HTTP::header value $aHeader]"
}

log local0. "  ----------- http_request_release ----------- "
log local0. " "
}
set http_request_time_release [clock clicks -milliseconds]
}

when LB_SELECTED {
if {$app_arrway_referer(http_lb_selected)} {
log local0. "  ----------- http_lb_selected ----------- "
log local0. "uid: $uid - pool member IP: [LB::server]"
log local0. "  ----------- http_lb_selected ----------- "
log local0. " "
}
}

when HTTP_RESPONSE {

set http_response_time [clock clicks -milliseconds]
set content_length [HTTP::header "Content-Length"]

if {$app_arrway_referer(http_response)} {
log local0. "  ----------- http_response ----------- "
log local0. "uid: $uid - status: [HTTP::status]"
log local0. "uid: $uid - pool member IP: [LB::server]"
foreach aHeader [HTTP::header names] {
log local0. "uid: $uid - $aHeader: [HTTP::header value $aHeader]"
}

log local0. "  ----------- http_response ----------- "
log local0. " "
}

if {$app_arrway_referer(http_response_payload)} {
if { $content_length > 0 && $content_length < 1048577 } {
set collect_length $content_length
} else {
set collect_length 1048576
} 

if { $collect_length > 0 } {
HTTP::collect $collect_length
}
}
}

when HTTP_RESPONSE_DATA {

if {$app_arrway_referer(http_response_payload)} {
log local0. "  ----------- http_response_payload ----------- "
set payload [HTTP::payload]  
log local0. "uid: $uid - Response (Body) payload: $payload"
log local0. "  ----------- http_response_payload ----------- "
log local0. " "
}
}

when HTTP_RESPONSE_RELEASE {

set http_response_time_release [clock clicks -milliseconds]

if {$app_arrway_referer(http_response_release)} {
log local0. "  ----------- http_response_release ----------- "
log local0. "uid: $uid - status: [HTTP::status]"
log local0. "uid: $uid - pool member IP: [LB::server]"
foreach aHeader [HTTP::header names] {
log local0. "uid: $uid - $aHeader: [HTTP::header value $aHeader]"
}
log local0. "  ----------- http_response_release ----------- "
log local0. " "
}

if {$app_arrway_referer(http_time_process)} {
log local0. "  ----------- http_time_process ----------- "
log local0.info "uid: $uid - Time to request  (F5 request time) = [expr $http_request_time - $http_request_time_release] (ms)"
log local0.info "uid: $uid - Time to response (F5 response time) = [expr $http_response_time - $http_response_time_release] (ms)"
log local0.info "uid: $uid - Time to server (server backend process time) = [expr $http_request_time_release - $http_response_time] (ms)"
log local0. "  ----------- http_time_process ----------- "
log local0. " "
}
}

when ACCESS_SESSION_STARTED {
if {$app_arrway_referer(apm_access)} {
        log local0.info " ------ Access Session Started -------" 
    }
}

when ACCESS_POLICY_COMPLETED {
if {$app_arrway_referer(apm_access)} {
        log local0.info " ------ Access Session Completed -------" 
    }
}

when ACCESS_SESSION_CLOSED {
if {$app_arrway_referer(apm_access)} {
        log local0.info " ------ Access Session Closed -------" 
    } 
}

when ACCESS_ACL_ALLOWED {
if {$app_arrway_referer(apm_access)} {
        log local0.info " ------ Access Session Allowed -------" 
    } 
}