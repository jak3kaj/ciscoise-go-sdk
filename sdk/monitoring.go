package isegosdk

import (
	"encoding/xml"

	"fmt"
	"strings"

	"github.com/go-resty/resty/v2"
)

type MonitoringService service

type Session struct {
	Server            *string   `xml:"server"`
	CallingStationID  *string   `xml:"calling_station_id"`
	AuditSessionID    *string   `xml:"audit_session_id"`
	AcctSessionID     *string   `xml:"acct_session_id"`
	NASIPAddress      *string   `xml:"nas_ip_address"`
	NASIPv6Address    *string   `xml:"nas_ipv6_address"`
	UserName          *string   `xml:"user_name"`
	FramedIPv6Address []*string `xml:"framed_ipv6_address>ipv6_address"`
}

type SessionParameters struct {
	Passed                      *string   `xml:"passed"`
	Failed                      *string   `xml:"failed"`
	UserName                    *string   `xml:"user_name"`
	NASIPAddress                *string   `xml:"nas_ip_address"`
	FailureReason               *string   `xml:"failure_reason"`
	CallingStationId            *string   `xml:"calling_station_id"`
	NASPort                     *string   `xml:"nas_port"`
	IdentityGroup               *string   `xml:"identity_group"`
	NetworkDeviceName           *string   `xml:"network_device_name"`
	ACSServer                   *string   `xml:"acs_server"`
	AuthenProtocol              *string   `xml:"authen_protocol"`
	FramedIPAddress             []*string `xml:"framed_ip_address>ip_address"`
	NetworkDeviceGroups         *string   `xml:"network_device_groups"`
	AccessService               *string   `xml:"access_service"`
	AuthACSTimestamp            *string   `xml:"auth_acs_timestamp"`
	AuthenticationMethod        *string   `xml:"authentication_method"`
	ExecutionSteps              *string   `xml:"execution_steps"`
	RadiusResponse              *string   `xml:"radius_response"`
	AuditSessionID              *string   `xml:"audit_session_id"`
	NASIdentifier               *string   `xml:"nas_identifier"`
	NASPortID                   *string   `xml:"nas_port_id"`
	NACPolicyCompliance         *string   `xml:"nac_policy_compliance"`
	AuthID                      *int      `xml:"auth_id"`
	AuthACSViewTimestamp        *string   `xml:"auth_acsview_timestamp"`
	MessageCode                 *string   `xml:"message_code"`
	ACSSessionID                *string   `xml:"acs_session_id"`
	ServiceSelectionPolicy      *string   `xml:"service_selection_policy"`
	AuthorizationPolicy         *string   `xml:"authorization_policy"`
	IdentityStore               *string   `xml:"identity_store"`
	Response                    *string   `xml:"response"`
	ServiceType                 *string   `xml:"service_type"`
	CTSSecurityGroup            *string   `xml:"cts_security_group"`
	UseCase                     *string   `xml:"use_case"`
	CiscoAVPair                 *string   `xml:"cisco_av_pair"`
	ADDomain                    *string   `xml:"ad_domain"`
	ACSUsername                 *string   `xml:"acs_username"`
	RadiusUsername              *string   `xml:"radius_username"`
	NACRole                     *string   `xml:"nac_role"`
	NACUsername                 *string   `xml:"nac_username"`
	NACPostureToken             *string   `xml:"nac_posture_token"`
	NACRadiusIsUserAuth         *string   `xml:"nac_radius_is_user_auth"`
	SelectedPostureServer       *string   `xml:"selected_posture_server"`
	SelectedIdentityStore       *string   `xml:"selected_identity_store"`
	AuthenticationIdentityStore *string   `xml:"authentication_identity_store"`
	AZNExpPolMatchedRule        *string   `xml:"azn_exp_pol_matched_rule"`
	ExtPolServerMatchedRule     *string   `xml:"ext_pol_server_matched_rule"`
	GRPMappingPolMatchedRule    *string   `xml:"grp_mapping_pol_matched_rule"`
	IdentityPolicyMatchedRule   *string   `xml:"identity_policy_matched_rule"`
	NASPortType                 *string   `xml:"nas_port_type"`
	QueryIdentityStores         *string   `xml:"query_identity_stores"`
	SelectedAZNProfiles         *string   `xml:"selected_azn_profiles"`
	SelExpAZNProfiles           *string   `xml:"sel_exp_azn_profiles"`
	SelectedQueryIdentityStores *string   `xml:"selected_query_identity_stores"`
	EAPTunnel                   *string   `xml:"eap_tunnel"`
	TunnelDetails               *string   `xml:"tunnel_details"`
	Ciscoh323Attributes         *string   `xml:"cisco_h323_attributes"`
	CiscoSSGAttributes          *string   `xml:"cisco_ssg_attributes"`
	OtherAttributes             *string   `xml:"other_attributes"`
	ResponseTime                *int      `xml:"response_time"`
	NADFailure                  *string   `xml:"nad_failure"`
	DestinationIPAddress        *string   `xml:"destination_ip_address"`
	AcctID                      *int      `xml:"acct_id"`
	AcctACSTimestamp            *string   `xml:"acct_acs_timestamp"`
	AcctACSViewTimestamp        *string   `xml:"acct_acsview_timestamp"`
	AcctSessionID               *string   `xml:"acct_session_id"`
	AcctStatusType              *string   `xml:"acct_status_type"`
	AcctSessionTime             *int      `xml:"acct_session_time"`
	AcctInputOctets             *string   `xml:"acct_input_octets"`
	AcctOutputOctets            *string   `xml:"acct_output_octets"`
	AcctInputPackets            *int      `xml:"acct_input_packets"`
	AcctOutputPackets           *int      `xml:"acct_output_packets"`
	AcctClass                   *string   `xml:"acct_class"`
	AcctTerminateCause          *string   `xml:"acct_terminate_cause"`
	AcctMultiSessionID          *string   `xml:"acct_multi_session_id"`
	AcctAuthentic               *string   `xml:"acct_authentic"`
	TerminationAction           *string   `xml:"termination_action"`
	SessionTimeout              *string   `xml:"session_timeout"`
	IdleTimeout                 *string   `xml:"idle_timeout"`
	AcctInterimInterval         *string   `xml:"acct_interim_interval"`
	AcctDelayTime               *string   `xml:"acct_delay_time"`
	EventTimestamp              *string   `xml:"event_timestamp"`
	AcctTunnelConnection        *string   `xml:"acct_tunnel_connection"`
	AcctTunnelPacketLost        *string   `xml:"acct_tunnel_packet_lost"`
	SecurityGroup               *string   `xml:"security_group"`
	Ciscoh323SetupTime          *string   `xml:"cisco_h323_setup_time"`
	Ciscoh323ConnectTime        *string   `xml:"cisco_h323_connect_time"`
	Ciscoh323DisconnectTime     *string   `xml:"cisco_h323_disconnect_time"`
	FramedProtocol              *string   `xml:"framed_protocol"`
	Started                     *string   `xml:"started"`
	Stopped                     *string   `xml:"stopped"`
	CkptID                      *int      `xml:"ckpt_id"`
	Type                        *int      `xml:"type"`
	NADACSViewTimestamp         *string   `xml:"nad_acsview_timestamp"`
	VLAN                        *string   `xml:"vlan"`
	DACL                        *string   `xml:"dacl"`
	AuthenticationType          *string   `xml:"authentication_type"`
	InterfaceName               *string   `xml:"interface_name"`
	Reason                      *string   `xml:"reason"`
	EndpointPolicy              *string   `xml:"endpoint_policy"`
	FramedIPv6Address           []*string `xml:"framed_ipv6_address>ipv6_address"`
	NASIPv6Address              *string   `xml:"nas_ipv6_address"`
}

type ResponseMonitoringGetActiveCount struct {
	Count *int `xml:"count,omitempty"` //
}

type ResponseMonitoringGetActiveList struct {
	NoOfActiveSession *int       `xml:"noOfActiveSession,attr"`
	ActiveSessions    []*Session `xml:"activeSession"`
}

type ResponseMonitoringGetSessionAuthList struct {
	NoOfActiveSession *int       `xml:"noOfActiveSession,attr"` //
	ActiveSessions    []*Session `xml:"activeSession"`
}

type ResponseMonitoringGetPostureCount struct {
	Count *int `xml:"count,omitempty"` //
}

type ResponseMonitoringGetProfilerCount struct {
	Count *int `xml:"count,omitempty"` //
}

type ResponseMonitoringGetDetailedSessions struct {
	SessionParameters []*SessionParameters `xml:"activeSession"`
}

type ResponseMonitoringGetMntVersion struct {
	XMLName    xml.Name `xml:"product"`
	Name       string   `xml:"name,omitempty"`         //
	Version    string   `xml:"version,omitempty"`      //
	TypeOfNode *int     `xml:"type_of_node,omitempty"` //
}

//GetActiveCount ActiveCount
/* ActiveCount

 */
func (s *MonitoringService) GetActiveCount() (*ResponseMonitoringGetActiveCount, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/ActiveCount"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetActiveCount{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		return nil, response, fmt.Errorf("error with operation GetActiveCount")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetActiveCount)
	return result, response, err

}

//GetActiveList ActiveList
/* ActiveList

 */
func (s *MonitoringService) GetActiveList() (*ResponseMonitoringGetActiveList, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/ActiveList"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetActiveList{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		return nil, response, fmt.Errorf("error with operation GetActiveList")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetActiveList)
	return result, response, err

}

//GetSessionAuthList Session/AuthList
/* Session/AuthList

 */
func (s *MonitoringService) GetSessionAuthList() (*ResponseMonitoringGetSessionAuthList, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/AuthList/null/null"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetSessionAuthList{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		return nil, response, fmt.Errorf("error with operation GetSessionAuthList")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetSessionAuthList)
	return result, response, err

}

//GetPostureCount PostureCount
/* PostureCount

 */
func (s *MonitoringService) GetPostureCount() (*ResponseMonitoringGetPostureCount, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/PostureCount"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetPostureCount{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		return nil, response, fmt.Errorf("error with operation GetPostureCount")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetPostureCount)
	return result, response, err

}

//GetProfilerCount ProfilerCount
/* ProfilerCount

 */
func (s *MonitoringService) GetProfilerCount() (*ResponseMonitoringGetProfilerCount, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/ProfilerCount"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetProfilerCount{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		return nil, response, fmt.Errorf("error with operation GetProfilerCount")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetProfilerCount)
	return result, response, err

}

//GetSessionsByMac Sessions by MAC
/* Sessions by MAC

@param mac mac path parameter.
*/
func (s *MonitoringService) GetSessionsByMac(mac string) (*ResponseMonitoringGetDetailedSessions, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/MACAddress/{mac}"
	path = strings.Replace(path, "{mac}", fmt.Sprintf("%v", mac), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetDetailedSessions{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetSessionsByMac")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

}

//GetSessionsByUsername Sessions by Username
/* Sessions by Username

@param username username path parameter.
*/
func (s *MonitoringService) GetSessionsByUsername(username string) (*ResponseMonitoringGetDetailedSessions, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/UserName/{username}"
	path = strings.Replace(path, "{username}", fmt.Sprintf("%v", username), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetDetailedSessions{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetSessionsByUsername")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

}

//GetSessionsByNasIP Sessions by NAS IP
/* Sessions by NAS IP

@param nasipv4 nas_ipv4 path parameter.
*/
func (s *MonitoringService) GetSessionsByNasIP(nasipv4 string) (*ResponseMonitoringGetDetailedSessions, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/IPAddress/{nas_ipv4}"
	path = strings.Replace(path, "{nas_ipv4}", fmt.Sprintf("%v", nasipv4), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetDetailedSessions{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetSessionsByNasIp")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

}

//GetSessionsByEndpointIP Sessions by Endpoint IP
/* Sessions by Endpoint IP

@param endpointipv4 endpoint_ipv4 path parameter.
*/
func (s *MonitoringService) GetSessionsByEndpointIP(endpointipv4 string) (*ResponseMonitoringGetDetailedSessions, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/EndPointIPAddress/{endpoint_ipv4}"
	path = strings.Replace(path, "{endpoint_ipv4}", fmt.Sprintf("%v", endpointipv4), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetDetailedSessions{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetSessionsByEndpointIp")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

}

//GetSessionsBySessionID Sessions by SessionID
/* Sessions by SessionID

@param sessionTypeID session_id path parameter.
*/
func (s *MonitoringService) GetSessionsBySessionID(sessionTypeID string) (*ResponseMonitoringGetDetailedSessions, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/Active/SessionID/{session_id}/0"
	path = strings.Replace(path, "{session_id}", fmt.Sprintf("%v", sessionTypeID), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetDetailedSessions{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetSessionsBySessionId")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

}

//GetMntVersion MNT Version
/* MNT Version

 */
func (s *MonitoringService) GetMntVersion() (*ResponseMonitoringGetMntVersion, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Version"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetMntVersion{}).
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		return nil, response, fmt.Errorf("error with operation GetMntVersion")
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetMntVersion)
	return result, response, err

}

//GetFailureReasons FailureReasons
/* FailureReasons

 */
func (s *MonitoringService) GetFailureReasons() (*resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/FailureReasons"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetFailureReasons")
	}

	getCSFRToken(response.Header())

	return response, err

}

//GetAuthenticationStatusByMac AuthenticationStatus by MAC
/* AuthenticationStatus by MAC

@param MAC MAC path parameter.
@param SECONDS SECONDS path parameter.
@param RECORDS RECORDS path parameter.
*/
func (s *MonitoringService) GetAuthenticationStatusByMac(MAC string, SECONDS string, RECORDS string) (*resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/AuthStatus/MACAddress/{MAC}/{SECONDS}/{RECORDS}/All"
	path = strings.Replace(path, "{MAC}", fmt.Sprintf("%v", MAC), -1)
	path = strings.Replace(path, "{SECONDS}", fmt.Sprintf("%v", SECONDS), -1)
	path = strings.Replace(path, "{RECORDS}", fmt.Sprintf("%v", RECORDS), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetAuthenticationStatusByMac")
	}

	getCSFRToken(response.Header())

	return response, err

}

//SessionReauthenticationByMac Session Reauthentication by MAC
/* Session Reauthentication by MAC

@param PSNNAME PSN_NAME path parameter.
@param ENDPOINTMAC ENDPOINT_MAC path parameter.
@param REAuthTYPE REAUTH_TYPE path parameter.
*/
func (s *MonitoringService) SessionReauthenticationByMac(PSNNAME string, ENDPOINTMAC string, REAuthTYPE string) (*resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/CoA/Reauth/{PSN_NAME}/{ENDPOINT_MAC}/{REAUTH_TYPE}"
	path = strings.Replace(path, "{PSN_NAME}", fmt.Sprintf("%v", PSNNAME), -1)
	path = strings.Replace(path, "{ENDPOINT_MAC}", fmt.Sprintf("%v", ENDPOINTMAC), -1)
	path = strings.Replace(path, "{REAUTH_TYPE}", fmt.Sprintf("%v", REAuthTYPE), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation SessionReauthenticationByMac")
	}

	getCSFRToken(response.Header())

	return response, err

}

//SessionDisconnect Session Disconnect
/* Session Disconnect

@param ENDPOINTIP ENDPOINT_IP path parameter.
@param PSNNAME PSN_NAME path parameter.
@param MAC MAC path parameter.
@param DISCONNECTTYPE DISCONNECT_TYPE path parameter.
@param NASIPV4 NAS_IPV4 path parameter.
*/
func (s *MonitoringService) SessionDisconnect(ENDPOINTIP string, PSNNAME string, MAC string, DISCONNECTTYPE string, NASIPV4 string) (*resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/CoA/Disconnect>/{PSN_NAME}/{MAC}/{DISCONNECT_TYPE}/{NAS_IPV4}/{{ENDPOINT_IP}}"
	path = strings.Replace(path, "{ENDPOINT_IP}", fmt.Sprintf("%v", ENDPOINTIP), -1)
	path = strings.Replace(path, "{PSN_NAME}", fmt.Sprintf("%v", PSNNAME), -1)
	path = strings.Replace(path, "{MAC}", fmt.Sprintf("%v", MAC), -1)
	path = strings.Replace(path, "{DISCONNECT_TYPE}", fmt.Sprintf("%v", DISCONNECTTYPE), -1)
	path = strings.Replace(path, "{NAS_IPV4}", fmt.Sprintf("%v", NASIPV4), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation SessionDisconnect")
	}

	getCSFRToken(response.Header())

	return response, err

}

//GetAccountStatusByMac AccountStatus by MAC
/* AccountStatus by MAC

@param mac mac path parameter.
@param duration duration path parameter.
*/
func (s *MonitoringService) GetAccountStatusByMac(mac string, duration string) (*resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/AcctStatus/MACAddress/{mac}/{duration}"
	path = strings.Replace(path, "{mac}", fmt.Sprintf("%v", mac), -1)
	path = strings.Replace(path, "{duration}", fmt.Sprintf("%v", duration), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(&Error).
		Get(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation GetAccountStatusByMac")
	}

	getCSFRToken(response.Header())

	return response, err

}

//DeleteAllSessions Delete All Sessions
/* Delete All Sessions

 */
func (s *MonitoringService) DeleteAllSessions() (*resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/Delete/All"

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(&Error).
		Delete(path)

	if err != nil {
		return nil, err

	}

	if response.IsError() {
		return response, fmt.Errorf("error with operation DeleteAllSessions")
	}

	getCSFRToken(response.Header())

	return response, err

}
