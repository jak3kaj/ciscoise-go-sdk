package isegosdk

import (
	"encoding/xml"

	"fmt"
	"strings"

	"github.com/go-resty/resty/v2"
)

// Renaming type to line up with Cisco ISE API documentation
type MonitoringService service

// Alias for backwards compatibility with original SDK
type MiscService = MonitoringService

type Session struct {
	AcctSessionID     string   `xml:"acct_session_id"`
	AuditSessionID    string   `xml:"audit_session_id"`
	CallingStationID  string   `xml:"calling_station_id"`
	FramedIPv6Address []string `xml:"framed_ipv6_address>ipv6_address"`
	NASIPAddress      string   `xml:"nas_ip_address"`
	NASIPv6Address    string   `xml:"nas_ipv6_address"`
	Server            string   `xml:"server"`
	UserName          string   `xml:"user_name"`
}

type SessionParameters struct {
	ACSServer                   string   `xml:"acs_server"`
	ACSSessionID                string   `xml:"acs_session_id"`
	ACSUsername                 string   `xml:"acs_username"`
	ADDomain                    string   `xml:"ad_domain"`
	AZNExpPolMatchedRule        string   `xml:"azn_exp_pol_matched_rule"`
	AccessService               string   `xml:"access_service"`
	AuthenticationIdentityStore string   `xml:"authentication_identity_store"`
	AcctACSTimestamp            string   `xml:"acct_acs_timestamp"`
	AcctACSViewTimestamp        string   `xml:"acct_acsview_timestamp"`
	AcctAuthentic               string   `xml:"acct_authentic"`
	AcctClass                   string   `xml:"acct_class"`
	AcctDelayTime               string   `xml:"acct_delay_time"`
	AcctID                      string   `xml:"acct_id"`
	AcctInputOctets             string   `xml:"acct_input_octets"`
	AcctInputPackets            string   `xml:"acct_input_packets"`
	AcctInterimInterval         string   `xml:"acct_interim_interval"`
	AcctOutputOctets            string   `xml:"acct_output_octets"`
	AcctOutputPackets           string   `xml:"acct_output_packets"`
	AcctSessionID               string   `xml:"acct_session_id"`
	AcctSessionTime             string   `xml:"acct_session_time"`
	AcctStatusType              string   `xml:"acct_status_type"`
	AcctTerminateCause          string   `xml:"acct_terminate_cause"`
	AcctTunnelConnection        string   `xml:"acct_tunnel_connection"`
	AcctTunnelPacketLost        string   `xml:"acct_tunnel_packet_lost"`
	AcctMultiSessionID          string   `xml:"acct_multi_session_id"`
	AuditSessionID              string   `xml:"audit_session_id"`
	AuthACSTimestamp            string   `xml:"auth_acs_timestamp"`
	AuthACSViewTimestamp        string   `xml:"auth_acsview_timestamp"`
	AuthID                      string   `xml:"auth_id"`
	AuthenProtocol              string   `xml:"authen_protocol"`
	AuthenticationMethod        string   `xml:"authentication_method"`
	AuthenticationProtocol      string   `xml:"authentication_protocol"`
	AuthenticationType          string   `xml:"authentication_type"`
	AuthorizationPolicy         string   `xml:"authorization_policy"`
	CPMSessionID                string   `xml:"cpm_session_id"`
	CTSSecurityGroup            string   `xml:"cts_security_group"`
	CallingStationID            string   `xml:"calling_station_id"`
	CiscoAVPair                 string   `xml:"cisco_av_pair"`
	CiscoSSGAttributes          string   `xml:"cisco_ssg_attributes"`
	Ciscoh323Attributes         string   `xml:"cisco_h323_attributes"`
	Ciscoh323ConnectTime        string   `xml:"cisco_h323_connect_time"`
	Ciscoh323DisconnectTime     string   `xml:"cisco_h323_disconnect_time"`
	Ciscoh323SetupTime          string   `xml:"cisco_h323_setup_time"`
	CkptID                      string   `xml:"ckpt_id"`
	DACL                        string   `xml:"dacl"`
	DestinationIPAddress        string   `xml:"destination_ip_address"`
	DeviceIPAddress             string   `xml:"device_ip_address"`
	DeviceType                  string   `xml:"device_type"`
	EAPTunnel                   string   `xml:"eap_tunnel"`
	EndpointPolicy              string   `xml:"endpoint_policy"`
	EventTimestamp              string   `xml:"event_timestamp"`
	ExecutionSteps              string   `xml:"execution_steps"`
	ExtPolServerMatchedRule     string   `xml:"ext_pol_server_matched_rule"`
	Failed                      string   `xml:"failed"`
	FailureReason               string   `xml:"failure_reason"`
	FramedIPAddress             string   `xml:"ip_address"`
	FramedIPv6Address           []string `xml:"framed_ipv6_address>ipv6_address"`
	FramedProtocol              string   `xml:"framed_protocol"`
	GRPMappingPolMatchedRule    string   `xml:"grp_mapping_pol_matched_rule"`
	IdentityGroup               string   `xml:"identity_group"`
	IdentityPolicyMatchedRule   string   `xml:"identity_policy_matched_rule"`
	IdentityStore               string   `xml:"identity_store"`
	IdleTimeout                 string   `xml:"idle_timeout"`
	InterfaceName               string   `xml:"interface_name"`
	Location                    string   `xml:"location"`
	MessageCode                 string   `xml:"message_code"`
	NACPolicyCompliance         string   `xml:"nac_policy_compliance"`
	NACPostureToken             string   `xml:"nac_posture_token"`
	NACRadiusIsUserAuth         string   `xml:"nac_radius_is_user_auth"`
	NACRole                     string   `xml:"nac_role"`
	NACUsername                 string   `xml:"nac_username"`
	NADACSViewTimestamp         string   `xml:"nad_acsview_timestamp"`
	NADFailure                  string   `xml:"nad_failure"`
	NASIdentifier               string   `xml:"nas_identifier"`
	NASIPAddress                string   `xml:"nas_ip_address"`
	NASIPv6Address              string   `xml:"nas_ipv6_address"`
	NASPort                     string   `xml:"nas_port"`
	NASPortID                   string   `xml:"nas_port_id"`
	NASPortType                 string   `xml:"nas_port_type"`
	NetworkDeviceGroups         string   `xml:"network_device_groups"`
	NetworkDeviceName           string   `xml:"network_device_name"`
	OrigCallingStationId        string   `xml:"orig_calling_station_id"`
	OtherAttributes             string   `xml:"other_attributes"`
	Passed                      string   `xml:"passed"`
	PostureStatus               string   `xml:"posture_status"`
	QueryIdentityStores         string   `xml:"query_identity_stores"`
	RadiusResponse              string   `xml:"radius_response"`
	RadiusUsername              string   `xml:"radius_username"`
	Response                    string   `xml:"response"`
	ResponseTime                string   `xml:"response_time"`
	Reason                      string   `xml:"reason"`
	SecurityGroup               string   `xml:"security_group"`
	SelExpAZNProfiles           string   `xml:"sel_exp_azn_profiles"`
	SelectedAZNProfiles         string   `xml:"selected_azn_profiles"`
	SelectedIdentityStore       string   `xml:"selected_identity_store"`
	SelectedPostureServer       string   `xml:"selected_posture_server"`
	SelectedQueryIdentityStores string   `xml:"selected_query_identity_stores"`
	ServiceSelectionPolicy      string   `xml:"service_selection_policy"`
	ServiceType                 string   `xml:"service_type"`
	SessionTimeout              string   `xml:"session_timeout"`
	Started                     string   `xml:"started"`
	Stopped                     string   `xml:"stopped"`
	TerminationAction           string   `xml:"termination_action"`
	TunnelDetails               string   `xml:"tunnel_details"`
	Type                        string   `xml:"type"`
	UseCase                     string   `xml:"use_case"`
	UserName                    string   `xml:"user_name"`
	VLAN                        string   `xml:"vlan"`
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

type ResponseMonitoringGetDetailedSessions SessionParameters

type ResponseMonitoringGetMntVersion struct {
	XMLName    xml.Name `xml:"product"`
	Name       string   `xml:"name,omitempty"`         //
	Version    string   `xml:"version,omitempty"`      //
	TypeOfNode *int     `xml:"type_of_node,omitempty"` //
}

type MntRestResult struct {
	CPMCode            string `xml:"cpm-code"`
	Description        string `xml:"description"`
	HTTPCode           string `xml:"http-code"`
	InternalErrorInfo  string `xml:"internal-error-info"`
	ModuleName         string `xml:"module-name"`
	RequestedOperation string `xml:"requested-operation"`
	ResourceID         string `xml:"resource-id"`
	ResourceName       string `xml:"resource-name"`
	ResourceType       string `xml:"resource-type"`
	Status             string `xml:"status"`
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
		SetError(MntRestResult{}).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		r := response.StatusCode()
		if (r >= 500 && r < 600) {
			err := response.Error().(*MntRestResult)
			return nil, response, fmt.Errorf("error with operation GetSessionsByMac - %s - %s\n", err.Description, err.InternalErrorInfo)
		} else {
			return nil, response, fmt.Errorf("error with operation GetSessionsByMac - HTTP Status: %d\n", r)
		}
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
		SetError(MntRestResult{}).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		r := response.StatusCode()
		if (r >= 500 && r < 600) {
			err := response.Error().(*MntRestResult)
			return nil, response, fmt.Errorf("error with operation GetSessionsByUsername - %s - %s\n", err.Description, err.InternalErrorInfo)
		} else {
			return nil, response, fmt.Errorf("error with operation GetSessionsByUsername - HTTP Status: %d\n", r)
		}
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
		SetError(MntRestResult{}).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		r := response.StatusCode()
		if (r >= 500 && r < 600) {
			err := response.Error().(*MntRestResult)
			return nil, response, fmt.Errorf("error with operation GetSessionsByNasIP - %s - %s\n", err.Description, err.InternalErrorInfo)
		} else {
			return nil, response, fmt.Errorf("error with operation GetSessionsByNasIP - HTTP Status: %d\n", r)
		}
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
		SetError(MntRestResult{}).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		r := response.StatusCode()
		if (r >= 500 && r < 600) {
			err := response.Error().(*MntRestResult)
			return nil, response, fmt.Errorf("error with operation GetSessionsByEndpointIP - %s - %s\n", err.Description, err.InternalErrorInfo)
		} else {
			return nil, response, fmt.Errorf("error with operation GetSessionsByEndpointIP - HTTP Status: %d\n", r)
		}
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

}

//GetSessionsBySessionID Sessions by SessionID
/* Sessions by SessionID

@param sessionTypeID session_id path parameter.
*/
func (s *MonitoringService) GetSessionsBySessionID(sessionTypeID string) (*ResponseMonitoringGetActiveList, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/Session/Active/SessionID/{session_id}/0"
	path = strings.Replace(path, "{session_id}", fmt.Sprintf("%v", sessionTypeID), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetResult(&ResponseMonitoringGetActiveList{}).
		SetError(MntRestResult{}).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		r := response.StatusCode()
		if (r >= 500 && r < 600) {
			err := response.Error().(*MntRestResult)
			return nil, response, fmt.Errorf("error with operation GetSessionsBySessionID - %s - %s\n", err.Description, err.InternalErrorInfo)
		} else {
			return nil, response, fmt.Errorf("error with operation GetSessionsBySessionID - HTTP Status: %d\n", r)
		}
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetActiveList)
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
func (s *MonitoringService) GetAuthenticationStatusByMac(MAC string, SECONDS string, RECORDS string) (*ResponseMonitoringGetDetailedSessions, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/AuthStatus/MACAddress/{MAC}/{SECONDS}/{RECORDS}/All"
	path = strings.Replace(path, "{MAC}", fmt.Sprintf("%v", MAC), -1)
	path = strings.Replace(path, "{SECONDS}", fmt.Sprintf("%v", SECONDS), -1)
	path = strings.Replace(path, "{RECORDS}", fmt.Sprintf("%v", RECORDS), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(MntRestResult{}).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		r := response.StatusCode()
		if (r >= 500 && r < 600) {
			err := response.Error().(*MntRestResult)
			return nil, response, fmt.Errorf("error with operation GetAuthenticationStatusByMac - %s - %s\n", err.Description, err.InternalErrorInfo)
		} else {
			return nil, response, fmt.Errorf("error with operation GetAuthenticationStatusByMac - HTTP Status: %d\n", r)
		}
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

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
		SetError(MntRestResult{}).
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
func (s *MonitoringService) GetAccountStatusByMac(mac string, duration string) (*ResponseMonitoringGetDetailedSessions, *resty.Response, error) {
	setHost(s.client, "_mnt")
	path := "/admin/API/mnt/AcctStatus/MACAddress/{mac}/{duration}"
	path = strings.Replace(path, "{mac}", fmt.Sprintf("%v", mac), -1)
	path = strings.Replace(path, "{duration}", fmt.Sprintf("%v", duration), -1)

	setCSRFToken(s.client)
	response, err := s.client.R().
		SetHeader("Content-Type", "application/xml").
		SetHeader("Accept", "application/xml").
		SetError(MntRestResult{}).
		Get(path)

	if err != nil {
		return nil, nil, err

	}

	if response.IsError() {
		r := response.StatusCode()
		if (r >= 500 && r < 600) {
			err := response.Error().(*MntRestResult)
			return nil, response, fmt.Errorf("error with operation GetAccountStatusByMac - %s - %s\n", err.Description, err.InternalErrorInfo)
		} else {
			return nil, response, fmt.Errorf("error with operation GetAccountStatusByMac - HTTP Status: %d\n", r)
		}
	}

	getCSFRToken(response.Header())

	result := response.Result().(*ResponseMonitoringGetDetailedSessions)
	return result, response, err

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
