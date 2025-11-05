#####################################################
# 
# Auto Generated python class by generate_api.sh
# 
#   OPENAPI File : resources/Console/V2/swagger.json
#   API title    : AITRIOS | Console
#   API version  : 2.0.0
# 
#####################################################
import sys
import os
import requests
import json
import inspect
import datetime
import mimetypes
from .utils import Utils

DEBUG_MODE = False

class AitriosConsole:

    def __init__(self, project_json):
        f = open(project_json, 'r')
        json_load = json.load(f)
        self.PROJECT_FILE = project_json
        self.BASE_URL = json_load['project']['baseURL']
        CLIENT_ID = json_load['project']['client_id']
        self.TENANT_ID = json_load['project']['tenant_id']
        CLIENT_SECRET = json_load['project']['client_secret']
        self.GCS_OKTA_DOMAIN = json_load['project']['gcs_okta_domain']
        self.AUTHORIZATION_CODE = Utils.Base64EncodedStr(CLIENT_ID + ":" + CLIENT_SECRET)
        f.close()

        self.DEVICE_ID = None
        self.DEVICE_NAME = None
        self.COMMAND_PARAM_FILE = None

    ##########################################################################
    # Low Level APIs
    ##########################################################################
    def GetToken(self):
        headers = {
            'accept': 'application/json',
            'authorization': 'Basic ' + self.AUTHORIZATION_CODE,
            'cache-control': 'no-cache',
            'content-type': 'application/x-www-form-urlencoded',
        }

        data = {
            'grant_type': 'client_credentials',
            'scope': 'system',
        }

        response = requests.post(
            url=self.GCS_OKTA_DOMAIN,
            data=data,
            headers=headers,
        )
        analysis_info = json.loads(response.text)
        token = analysis_info["access_token"]
        return token

    def InitHeaderParam(self):
        token = self.GetToken()
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token
        }
        return headers
    
    def Request(self, url, method, headers, **kwargs):
        params={}
        payload = {}
        url = self.BASE_URL + url
        response = None
        analysis_info = None
        files = None
        is_multipart_form_data = False

        # check 'multipart/form-data'
        if 'Content-Type' in headers:
            is_multipart_form_data = (headers['Content-Type'] == 'multipart/form-data')

        # set parameters
        for key, val in kwargs.items() :
            if val != None:
                if key == 'payload':
                    # payload
                    # patch for UploadFile()
                    if is_multipart_form_data:
                        file = val['file']
                        payload = {'type_code': val['type_code']}
                    else:
                        payload = json.dumps(val)
                elif key == 'content_type':
                    # content type
                    content_type = str(val)
                else:
                    # check parameters
                    if '{' + key + '}' in url:
                        # path parameter
                        url = url.replace('{' + key + '}', val)
                    else:
                        # query parameter
                        params.setdefault(key, str(val))

        # call request
        try:
            # patch for UploadFile()
            if is_multipart_form_data:
                mime_type, _ = mimetypes.guess_type(url=file)
                if mime_type == None:
                    mime_type = 'application/octet-stream'
                print('Guessed MIME type: ' + str(mime_type))
                files = {'file': (file, open(file, 'rb'), mime_type)}

                # remove 'Content-Type':'multipart/form-data' from header
                del headers['Content-Type']

            response = requests.request(method=method, url=url, headers=headers, files=files, params=params, data=payload)
            analysis_info = json.loads(response.text)
        except Exception as e:
            return response.text
        return analysis_info

    def GetApiVersion(self):
        # added by generate_api.h
        return "2.0.0"

    def debug_print(func):
        def wrapper(*args, **kwargs):
            if DEBUG_MODE:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                frame = inspect.currentframe().f_back
                line_number = frame.f_lineno
                file_name = inspect.getframeinfo(frame).filename
                print(f"[DEBUG] {timestamp}: [{file_name}:{line_number}] {func.__name__}")
            return func(*args, **kwargs)
        return wrapper

    @debug_print
    def DownloadFile(self, url, file_name):
        try:
            response = requests.get(url=url, stream=True)
            response.raise_for_status()
            with open(file_name, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            return response
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
            return None
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
            return None
        except IOError as io_err:
            print(f"I/O error occurred: {io_err}")
            return None
        except Exception as err:
            print(f"An error occurred: {err}")
            return None

    ##################################################################
    # Auto-generated by GenerateAitriosApi.py from here:
    ##################################################################

    @debug_print
    def GetQrCodeForProvisioning(self, ntp:str=None, auto:bool=None, wifi_ssid:str=None, wifi_pass:str=None, proxy_url:str=None, proxy_port:str=None, proxy_user_name:str=None, proxy_pass:str=None, ip_address:str=None, subnet_mask:str=None, gateway:str=None, dns:str=None, grant_type:str=None):
        """
		Returns a QR in base64-encoded format to provision the Edge Device.

		Parameters:
		------------------------------
		ntp : str
			NTP server. The maximum number of characters that can be specified is 64.
		auto : bool
			QR type.
			- Value definition:  
			  true: Generates an Enrollment QR for auto enrollment.  
			  false: Generates a Service QR for manual enrollment.  
			Default value : False
		wifi_ssid : str
			SSID information to connect the Wi-Fi network.
		wifi_pass : str
			Password to connect the Wi-Fi network.
		proxy_url : str
			URL of the proxy server.
		proxy_port : str
			Port number of the proxy server.
		proxy_user_name : str
			Username to access the proxy server.
		proxy_pass : str
			Password to access the proxy server.
		ip_address : str
			IP address assigned to the device. The maximum number of characters that can be specified is 39.
		subnet_mask : str
			Subnet mask applied to the device. The maximum number of characters that can be specified is 39.
		gateway : str
			Gateway to connect the device. The maximum number of characters that can be specified is 39.
		dns : str
			DNS information of the server. The maximum number of characters that can be specified is 39.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
			contents : string (required)
				QR (base64 encoding).
			expiration_date : string
				The expiration date of QR for auto enrollment.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0030001  
				  Invalid parameter wifi_ssid.  
				- E.SC.API.0030002  
				  Invalid parameter wifi_pass.  
				- E.SC.API.0030003  
				  Invalid parameter manifest_file_url.  
				- E.SC.API.0030004  
				  Invalid parameter proxy_url.  
				- E.SC.API.0030005  
				  Invalid parameter proxy_port.  
				- E.SC.API.0030006  
				  Invalid parameter proxy_user_name.  
				- E.SC.API.0030007  
				  Invalid parameter proxy_pass.  
				- E.SC.API.0030008  
				  Invalid parameter ip_address.  
				- E.SC.API.0030009  
				  Invalid parameter subnet_mask.  
				- E.SC.API.0030010  
				  Invalid parameter gateway.  
				- E.SC.API.0030011  
				  Invalid parameter dns.  
				- E.SC.API.0030012  
				  Invalid parameter ntp.  
				- E.SC.API.0030013  
				  Parameter ntp is not set.  
				- E.SC.API.0030014  
				  Invalid parameter auto.  
				- E.SC.API.0030015  
				  Invalid parameter ip_address_ipv6.  
				- E.SC.API.0030016  
				  Invalid parameter subnet_mask_ipv6.  
				- E.SC.API.0030017  
				  Invalid parameter gateway_ipv6.  
				- E.SC.API.0030018  
				  Invalid parameter dns_ipv6.  
				- E.SC.API.0030019  
				  Parameter device_type is not set.  
				- E.SC.API.0030020  
				  Invalid parameter device_type.  
				- E.SC.API.0030021  
				  Parameter dhcp is not set.  
				- E.SC.API.0030022  
				  Invalid parameter dhcp.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/provisioning/qrcode', headers=headers, method='GET', ntp=ntp, auto=auto, wifi_ssid=wifi_ssid, wifi_pass=wifi_pass, proxy_url=proxy_url, proxy_port=proxy_port, proxy_user_name=proxy_user_name, proxy_pass=proxy_pass, ip_address=ip_address, subnet_mask=subnet_mask, gateway=gateway, dns=dns, grant_type=grant_type)
        return ret

    @debug_print
    def EnrollDevice(self, payload, grant_type:str=None):
        """
		Registers your Edge Device with a device certificate.  
		Assumptions and Notes:    
		  ・Certification format: Primary device X.509 certificate (.pem file, .cer file, or .crt file).

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		device_name : string (required)
			Device name.
			The maximum number of characters that can be specified is 255.
		primary_certificate : string (required)
			Specify the string data of the X.509 primary certificate (.pem file or .cer file) for the subject device.
			*The data should not include the leading signatures, trailing signatures, or line breaks.  
			-----BEGIN CERTIFICATE-----  
			-----END CERTIFICATE-----  
		device_version : string
			Device version.  
			If device type is SZP123S-001, CSV26, or AIH-IVRW2, need to determine the version of the device based on the LED lighting patterns.  
			For information on the LED lighting patterns, please refer to the Installation Guide in the Developer Site.  
			Enum:
				'v1'
				'v2'

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
			id : string
				The registered device ID.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0144001  
				  Json format is invalid.  
				- E.SC.API.0144002  
				  Parameter device_name is not set.  
				- E.SC.API.0144003  
				  Invalid parameter device_name.  
				- E.SC.API.0144004  
				  Parameter device_type is not set.  
				- E.SC.API.0144005  
				  Parameter primary_certificate is not set.  
				- E.SC.API.0144006  
				  The specified parameter device_name is registered.  
				- E.SC.API.0144008  
				  The specified certificate is registered.  
				- E.SC.API.0144009  
				  The specified certificate is registered by some device.  
				- E.SC.API.0144010  
				  An invalid or already enrolled device certificate was specified.  
				- E.SC.API.0144011  
				  The device of the specified certificate is already registered in another project.  
				- E.SC.API.0144012  
				  Invalid parameter device_version.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0144007  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/devices', headers=headers, method='POST', payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetDevices(self, limit:int=None, starting_after:str=None, connection_state:str=None, device_name:str=None, device_id:str=None, device_group_id:str=None, device_ids:str=None, grant_type:str=None):
        """
		Lists the information of Edge Devices specified by query parameters.  
		This API does not retrieve Edge Application properties. To retrieve them, please use the GetDevice API or GetProperty API.

		Parameters:
		------------------------------
		limit : int
			Number of the items to fetch information. If the parameter (connection_state) is Disconnected, the actual amount of data retrievable will be less than the set limit value.  
			Value range: 1 to 1000
			Default value : 500
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		connection_state : str
			Connection state.
			- Value definition:  
			  Connected  
			  Disconnected
		device_name : str
			Name of the device. *Fuzzy searching is available.
		device_id : str
			Device ID. *Fuzzy searching is available.
		device_group_id : str
			Name of the device group.
		device_ids : str
			To specify multiple device IDs, separate them with commas.
		scope
			The scope of response parameters to return.
			 - Value definition:  
			  full: Returns all parameters  
			  minimal: Returns minimal parameters *effective for timesaving
			Default value : full
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string
				Last token of extracted data. If there is no continuation data, it will be empty.
			devices : array (required)
				device_id : string (required)
					The device ID.
				description : string
					The description of the device.
				device_name : string
					The device name.
				internal_device_id : string
					The internal device ID.
				device_type : string
					The device type.
				ins_id : string
					The subject that registered the device.
				ins_date : string
					The date the device was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				upd_id : string
					The subject that updated the device.
				upd_date : string
					The date the device was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				connection_state : string
					The device connection state.
				last_activity_time : string
					The date the device last connected.
				inactivity_timeout : number
					Time the device is considered inactive.
				models : array
					model_id : string
						The model ID.
					model_version_id : string
						The model version ID.
				property : object
					The properties of Edge System Software
					configuration : object
					state : object
				modules : array
					module_id : string
						The module id of Edge Application
					module_name : string
					property : object
						configuration : object
						state : object
				device_groups : array
					device_group_id : string (required)
						The device group ID.
					description : string (required)
						The device group description.
					ins_id : string (required)
						The subject that created the device group.
					ins_date : string (required)
						The date the device group was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
					upd_id : string (required)
						The subject that updated the device group.
					upd_date : string (required)
						The date the device group was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below: 
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0001003
				  Invalid parameter limit.
				- E.SC.API.0001004
				  Invalid parameter starting after.
				- E.SC.API.0001005
				  Invalid parameter scope.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0000011  
				  Timeout occurred when requesting.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices', headers=headers, method='GET', limit=limit, starting_after=starting_after, connection_state=connection_state, device_name=device_name, device_id=device_id, device_group_id=device_group_id, device_ids=device_ids, grant_type=grant_type)
        return ret

    @debug_print
    def GetDevice(self, device_id:str, grant_type:str=None):
        """
		Returns the information of an Edge Device specified by query parameters.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			device_id : string (required)
				The device ID.
			description : string
				The description of the device.
			device_name : string
				The device name.
			internal_device_id : string
				The internal device ID.
			device_type : string
				The device type.
			ins_id : string (required)
				The subject that registered the device.
			ins_date : string (required)
				The date the device was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			upd_id : string (required)
				The subject that updated the device.
			upd_date : string (required)
				The date the device was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			connection_state : string (required)
				The device connection state.
			last_activity_time : string (required)
				The date the device last connected.
			inactivity_timeout : number (required)
				Time the device is considered inactive.
			models : array
				model_id : string
					The model ID.
				model_version_id : string
					The model version ID. Format: modelid:v1.01  
					*For model that does not exist in the system, display network_id  
					  Example: 000237  
			device_groups : array
				device_group_id : string (required)
					The device group ID.
				description : string
					The device group description.
				ins_id : string (required)
					The subject that created the device group.
				ins_date : string (required)
					The date the device group was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				upd_id : string (required)
					The subject that updated the device group.
				upd_date : string (required)
					The date the device group was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			modules : array
				module_id : string
					If the target is Edge System Software, a value of $system will be returned.
				module_name : string
				property : object
					configuration : object
					state : object
			property : object
				Firmware information of the device
				state : object
					Current firmware state.
				configuration : object
					Desired firmware configuration
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0002001  
				  Not found.  
				- E.SC.API.0002002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0000011  
				  Timeout occurred when requesting.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}', headers=headers, method='GET', device_id=device_id, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateDevice(self, device_id:str, payload, grant_type:str=None):
        """
		Updates the information of a specific Edge Device specified by path parameters.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		device_name : string
			Device name.
			The maximum number of characters that can be specified is 255.
		description : string
			Device description. The maximum number of characters that can be specified is 100.
		inactivity_timeout : number
			Time the device is considered inactive. 60 ~ 600 [sec]

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0291003  
				  Invalid parameter device_name. Device names should be in single-byte characters and the maximum number of characters that can be specified is 255.
				- E.SC.API.0291004  
				  Invalid parameter inactivity_timeout.  
				- E.SC.API.0291008  
				  The specified parameter device_name is registered.  
				- E.SC.API.0291010  
				  Invalid parameter description. The maximum number of characters that can be specified is 100.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0291005  
				  Not found.  
				- E.SC.API.0291009  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0291006  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/devices/{device_id}', headers=headers, method='PATCH', device_id=device_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteDevice(self, device_id:str, grant_type:str=None):
        """
		Deletes the registered Edge Device (device_id) from the Console.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- W.SC.API.0111001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- W.SC.API.0111002  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}', headers=headers, method='DELETE', device_id=device_id, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceCertificates(self, limit:int=None, starting_after:str=None, grant_type:str=None):
        """
		Lists the Edge Device certificate information.

		Parameters:
		------------------------------
		limit : int
			Number of the items to fetch information.
			Value range: 1 to 256
			Default value : 100
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			certificates : array (required)
				device_id : string
					The device ID.
				internal_device_id : string
					The internal device ID.
				device_name : string
					The device name.
				credentials_id_object : string
					The credentials id object. *This response is not intended for customer utilization.
				credentials_type : string
					The credentials type.
				expiration_date : string
					The expiration date.
				created_time : string
					The created time.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0096001
				  Invalid parameter limit.
				- E.SC.API.0096002
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/certificates', headers=headers, method='GET', limit=limit, starting_after=starting_after, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceCertificate(self, device_id:str, grant_type:str=None):
        """
		The information for a specific Edge Device (device ID) within a group.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			device_id : string
				The device ID.
			internal_device_id : string
				The internal device ID.
			device_name : string
				The device name.
			credentials_id_object : string
				The credentials id object. *This response is not intended for customer utilization.
			credentials_type : string
				The credentials type.
			expiration_date : string
				The expiration date.
			created_time : string
				The created time.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0097001  
				  Not found.  
				- E.SC.API.0097002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/certificates/{device_id}', headers=headers, method='GET', device_id=device_id, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateDeviceCertificate(self, device_id:str, payload, grant_type:str=None):
        """
		Updates the device certificate information for a specific Edge Device.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		primary_certificate : string
			Specify the string data of the X.509 primary certificate (.pem file or .cer file) for the subject device.  
			*The data should not include the leading signatures, trailing signatures, or line breaks.  
			-----BEGIN CERTIFICATE-----  
			-----END CERTIFICATE-----  
		device_name : string
			Device Name. The maximum number of characters that can be specified is 255.   

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0091001  
				  Json format is invalid.  
				- E.SC.API.0091002  
				  Parameter device_id is not set.  
				- E.SC.API.0091007  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0091005  
				  Not found.  
				- E.SC.API.0091009  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0091006  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/certificates/{device_id}', headers=headers, method='PUT', device_id=device_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceProperty(self, device_id:str, grant_type:str=None):
        """
		Get Property of the Edge System Software. Property is a data format for storing information about the Edge System Software on a device. Property includes Configuration which is used to set desired state from the cloud to the device, and State which is used to report current state from the device to the cloud.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			configuration : object
			state : object
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0304001  
				  Not found.  
				- E.SC.API.0304002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}/property', headers=headers, method='GET', device_id=device_id, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateDeviceConfiguration(self, device_id:str, payload, include_updated_conf:bool=None, grant_type:str=None):
        """
		Updates the Configuration of a device. All fields under the specified Property name will be updated.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		include_updated_conf : bool
			Whether the response includes updated Configuration or not.
			Default value : False
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		configuration : object

		Returns:
		------------------------------
		[200] Successful Response:
			result : string
				SUCCESS
			configuration : 
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0306001  
				  Invalid parameter device_id.  
				- E.SC.API.0306002  
				  A value of a property is invalid due to the limitations of the property or invalid type.  
				- E.SC.API.0306003  
				  A Value is missing when building the payload.  
				- E.SC.API.0306004  
				  payload validation is not passed.  
				- E.SC.API.0306005  
				  The value is against the rules of payload.  
				- E.SC.API.0306006  
				  The DTMI is not registered .  
				- E.SC.API.0306007  
				  The device type is not supported.  
				- E.SC.API.0306008  
				  The device type does not support the twin .  
				- E.SC.API.0306009  
				  Unable to connect to device.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/devices/{device_id}/property', headers=headers, method='PATCH', device_id=device_id, payload=payload, include_updated_conf=include_updated_conf, grant_type=grant_type)
        return ret

    @debug_print
    def GetProperty(self, device_id:str, module_id:str, grant_type:str=None):
        """
		Get Property of a specified module. Property is a data format for storing information about the Edge System Software or Edge Applications on a device.​ Property includes Configuration which is used to set desired state from the cloud to the device, and State which is used to report current state from the device to the cloud.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		module_id : str (required) 
			Module ID. When the destination is System App, specify $system.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			property : 
			module_id : string
			$metadata : object
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0285001  
				  Not found.  
				- E.SC.API.0285002  
				  Not found.  
				- E.SC.API.0285003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[409] Conflict:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0285004  
				  The specified module_id has not been deployed.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}/modules/{module_id}', headers=headers, method='GET', device_id=device_id, module_id=module_id, grant_type=grant_type)
        return ret

    @debug_print
    def GetModuleProperty(self, device_id:str, module_id:str, grant_type:str=None):
        """
		Get Property of a specified module. Property is a data format for storing information about the Edge Applications on a device. Property includes Configuration which is used to set desired state from the cloud to the device, and State which is used to report current state from the device to the cloud.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		module_id : str (required) 
			Module ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			configuration : object
			state : object
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0305001  
				  Not found.  
				- E.SC.API.0305002  
				  Not found.  
				- E.SC.API.0305003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}/modules/{module_id}/property', headers=headers, method='GET', device_id=device_id, module_id=module_id, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateModuleConfiguration(self, device_id:str, module_id:str, payload, include_updated_conf:bool=None, grant_type:str=None):
        """
		Updates the Configuration of a specific module. All fields under the specified Property name will be updated.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		module_id : str (required) 
			Module ID.
		include_updated_conf : bool
			Whether the response includes updated Configuration or not.
			Default value : False
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		configuration : object

		Returns:
		------------------------------
		[200] Successful Response:
			result : string
				SUCCESS
			configuration : 
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0307001  
				  Invalid parameter device_id.  
				- E.SC.API.0307002  
				  Invalid parameter module_id.  
				- E.SC.API.0307003  
				  A value of a property is invalid due to the limitations of the property or invalid type.  
				- E.SC.API.0307004  
				  A Value is missing when building the payload.  
				- E.SC.API.0307005  
				  payload validation is not passed.  
				- E.SC.API.0307006  
				  The value is against the rules of payload.  
				- E.SC.API.0307007  
				  The DTMI is not registered .  
				- E.SC.API.0307008  
				  The device type is not supported.  
				- E.SC.API.0307009  
				  The device type does not support the twin .  
				- E.SC.API.0307010  
				  Unable to connect to device.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/devices/{device_id}/modules/{module_id}/property', headers=headers, method='PATCH', device_id=device_id, module_id=module_id, payload=payload, include_updated_conf=include_updated_conf, grant_type=grant_type)
        return ret

    @debug_print
    def ExecuteDeviceCommand(self, device_id:str, payload, grant_type:str=None):
        """
		Synchronously executes commands like device initialization and rebooting based on the parameters defined in the DTDL.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		command_name : string (required)
		parameters : object

		Returns:
		------------------------------
		[200] Successful Response (Response from the device must be included in this HTTP response body as "command_response". Respond with 200 HTTP status code regardless of response from the device. If the response from device is not SUCCESS, response parameter "result" should be WARNING):
			result : string (required)
				SUCCESS or WARNING.
			command_response : object
				Response from the device.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0308001  
				  Invalid parameter device_id.  
				- E.SC.API.0308002  
				  Parameter command_name is not set.  
				- E.SC.API.0308003  
				  Unable to connect to Device.  
				- E.SC.API.0308004  
				  A Value is missing when building the payload.  
				- E.SC.API.0308005  
				  A value of a property is invalid due to the limitations of the property or invalid type.  
				- E.SC.API.0308006  
				  The parameter is missing when building the payload.  
				- E.SC.API.0308007  
				  Payload validation is not passed.  
				- E.SC.API.0308008  
				  The value is against the rules of payload.  
				- E.SC.API.0308009  
				  The DTMI is not registered.  
				- E.SC.API.0308010  
				  The device type is not supported.  
				- E.SC.API.0308011  
				  The device type does not support the command.  
				- E.SC.API.0308012  
				  Unable to connect to device.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[408] Request Timeout:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000009  
				  Timeout occurred when requesting device.  
			time : string (required)
				The time the error occurred.*yyyy-MM-ddTHH:mm:ss.SSSSSS.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/devices/{device_id}/command', headers=headers, method='POST', device_id=device_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def ExecuteCommand(self, device_id:str, module_id:str, payload, grant_type:str=None):
        """
		Synchronously executes commands like device initialization and rebooting based on the parameters defined in the DTDL.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		module_id : str (required) 
			Module ID. When the destination is System App, specify $system.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		command_name : string (required)
		parameters : object

		Returns:
		------------------------------
		[200] Successful Response (Response from the device must be included in this HTTP response body as "command_response". Respond with 200 HTTP status code regardless of response from the device. If the response from device is not SUCCESS, response parameter "result" should be WARNING):
			result : string (required)
				SUCCESS or WARNING.
			code : string
				Error code.
			message : string
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- W.SC.API.0288007  
				  Device responded with an error when requested. Result = {0}  
			time : string
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0288001  
				  Invalid parameter device_id.  
				- E.SC.API.0288002  
				  Parameter command_name is not set.  
				- E.SC.API.0288003  
				  Invalid Parameter contents.  
				- E.SC.API.0288005  
				  Unable to connect to Device.  
				- E.SC.API.0288006  
				  Invalid parameter module_id.  
				- E.SC.API.0288008  
				  payload validation is not passed.  
				- E.SC.API.0288009  
				  A Value is missing when building the payload.  
				- E.SC.API.0288010  
				  A value of a property is invalid due to the limitations of the property or invalid type.  
				- E.SC.API.0288011  
				  The value is against the rules of payload.  
				- E.SC.API.0288012  
				  The DTMI is not registered.  
				- E.SC.API.0288013  
				  The device type does not support the command.  
				- E.SC.API.0288014  
				  Unable to connect to device.  
				- E.SC.API.0288015  
				  The device type is not supported.  
				- E.SC.API.0288016  
				  The parameter is missing when building the payload.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[408] Request Timeout:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000009  
				  Timeout occurred when requesting device.  
			time : string (required)
				The time the error occurred.*yyyy-MM-ddTHH:mm:ss.SSSSSS.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/devices/{device_id}/modules/{module_id}/command', headers=headers, method='POST', device_id=device_id, module_id=module_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeployConfigurations(self, limit:int=None, starting_after:str=None, grant_type:str=None):
        """
		Extracts and lists the settings of the Deploy Configuration.

		Parameters:
		------------------------------
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 20
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			deploy_configs : array (required)
				config_id : string (required)
					The config ID.
				description : string (required)
					The config description.
				running_cnt : integer (required)
					Returns the running cnt.
				success_cnt : integer (required)
					Returns the success cnt.
				fail_cnt : integer (required)
					Returns the fail cnt.
				edge_system_sw_package : object (required)
					firmware_id : string
						The Edge System Software Package firmware ID.
					firmware_version : string
						The Edge System Software Package version.
				models : array (required)
					model_id : string
						The model ID.
					model_version_number : string
						The model version number.
					model_comment : string
						The model comment.
					model_version_comment : string
						The model version comment.
				edge_apps : array (required)
					app_name : string
						The name of the Edge Application.
					app_version : string
						The application version.
					description : string
						The description of the application.
				model_bundles : array (required)
					model_bundle_name : string
						The model bundle name.
					model_bundle_version : string
						The model bundle version.
					description : string
						The description of the model bundle.
				ins_id : string (required)
					The subject that registered the deployment.
				ins_date : string (required)
					The date the deployment was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				upd_id : string (required)
					The subject that updated the deployment.
				upd_date : string (required)
					The date the deployment was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0020001
				  Invalid parameter limit.
				- E.SC.API.0020002
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/deploy_configs', headers=headers, method='GET', limit=limit, starting_after=starting_after, grant_type=grant_type)
        return ret

    @debug_print
    def CreateDeployConfiguration(self, payload=None, grant_type:str=None):
        """
		Creates the Deploy Configuration. The registration will include the following features:
		- Edge System Software
		- AI model
		- Edge App
		- AI model bundle

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		config_id : string (required)
			The maximum number of characters that can be specified is 100 single-byte ones.
		description : string
			The maximum number of characters that can be specified is 100.
		models : array
			model_id : string
				ID of the AI model.
			model_version_number : string
				Model version number.
		edge_system_sw_package : object
			firmware_id : string
				Edge System SW Package firmware ID.
		edge_apps : array
			app_name : string
			app_version : string
		model_bundles : array
			model_bundle_name : string
			model_bundle_version : string

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0022001  
				  Parameter config_id is not set.  
				- E.SC.API.0022002  
				  Invalid parameter config_id.  
				- E.SC.API.0022010  
				  The specified parameter config_id is registered.  
				- E.SC.API.0022023  
				  Invalid parameter description.  
				- E.SC.API.0022017  
				  Bad request.  
				- E.SC.API.0022018  
				  Invalid parameter edge_system_sw_package.  
				- E.SC.API.0022019  
				  Invalid parameter models or edge_apps or model_bundles.  
				- E.SC.API.0022021  
				  Invalid parameter model_ids.  
				- E.SC.API.0022022  
				  Invalid parameter edge_apps.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0022011  
				  Not found.  
				- E.SC.API.0022012  
				  Not found.  
				- E.SC.API.0022013  
				  Not found.  
				- E.SC.API.0022024  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/deploy_configs', headers=headers, method='POST', payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeployConfiguration(self, config_id:str, grant_type:str=None):
        """
		Lists the information of specified Deploy Configuration.

		Parameters:
		------------------------------
		config_id : str (required) 
			Deploy Configuration ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			config_id : string (required)
				The config ID.
			description : string (required)
				The config description.
			running_cnt : integer (required)
				Returns the running cnt.
			success_cnt : integer (required)
				Returns the success cnt.
			fail_cnt : integer (required)
				Returns the fail cnt.
			edge_system_sw_package : object (required)
				firmware_id : string
					The Edge System Software Package firmware ID.
				firmware_version : string
					The Edge System Software Package version.
			models : array (required)
				model_id : string
					The model ID.
				model_version_number : string
					The model version number.
				model_comment : string
					The model comment.
				model_version_comment : string
					The model version comment.
			edge_apps : array (required)
				app_name : string
					The name of the Edge Application.
				app_version : string
					The application version.
				description : string
					The description of the application.
			model_bundles : array (required)
				model_bundle_name : string
					The model bundle name.
				model_bundle_version : string
					The model bundle version.
				description : string
					The description of the model bundle.
			ins_id : string (required)
				The subject that registered the deployment.
			ins_date : string (required)
				The date the deployment was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			upd_id : string (required)
				The subject that updated the deployment.
			upd_date : string (required)
				The date the deployment was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
			time : string (required)
				The timestamp of the error occurrence. *yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0021001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/deploy_configs/{config_id}', headers=headers, method='GET', config_id=config_id, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteDeployConfiguration(self, config_id:str, grant_type:str=None):
        """
		Deletes the specified Deploy Configuration.

		Parameters:
		------------------------------
		config_id : str (required) 
			Configuration ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0055002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/deploy_configs/{config_id}', headers=headers, method='DELETE', config_id=config_id, grant_type=grant_type)
        return ret

    @debug_print
    def DeployByConfiguration(self, config_id:str, payload, grant_type:str=None):
        """
		   Deploys the following features specified by the Deploy Configuration to Edge Devices: 
		   - Edge System Software   
		   - AI model
		   - Edge App

		Parameters:
		------------------------------
		config_id : str (required) 
			Setting ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		device_ids : array (required)
			Specify multiple device IDs.
		description : string
			Maximum is 100 characters.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
			deploy_id : string (required)
				ID from sc_t_deploy.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0027001  
				  Parameter device_ids is not set.  
				- E.SC.API.0027005  
				  Bad request.  
				- E.SC.API.0027006  
				  Unable to connect to device. device_ids = {0}  
				- E.SC.API.0027010  
				  Invalid parameter device_id.  
				- E.SC.API.0027011  
				  Bad request.  
				- E.SC.API.0027017  
				  Model includes DCPU, but device does not support DCPU. device_ids = {0}
				- E.SC.API.0027018  
				  Invalid parameter description.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0027015  
				  Unauthorized operation.  
				- E.SC.API.0027019  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0027003  
				  Not found.  
				- E.SC.API.0027004  
				  Not found.   
				- E.SC.API.0027014  
				  Model does not found.  
				- E.SC.API.0027016  
				  Device app does not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.   
				- E.SC.API.0027020  
				  Internal server error.   
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/deploy_configs/{config_id}/apply', headers=headers, method='POST', config_id=config_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def CancelDeployment(self, device_id:str, deploy_id:str, grant_type:str=None):
        """
		Cancels the deployment of core features such as Edge System softwares, AI models, and Edge Applications that run on the Edge Device. This operation cancels the deployment for Edge Devices that have not yet received it. If the device already received the deployment, this operation does not change anything.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID
		deploy_id : str (required) 
			Deploy ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0166003  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0166001  
				  Not found.  
				- E.SC.API.0166002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0166004  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}/deploys/{deploy_id}/cancel', headers=headers, method='POST', device_id=device_id, deploy_id=deploy_id, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceDeployHistory(self, device_id:str, limit:int=None, starting_after:str=None, grant_type:str=None):
        """
		Returns the deployment history of core features such as Edge System softwares, AI models, and Edge Applications that run on the Edge Device.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 20
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			deploys : array (required)
				deploy_id : string (required)
					Deploy ID.
				deploy_type : string (required)
					The deploy type.
					Enum:
						'deploy_config'
						'device_model'
				deploy_status : string (required)
					The deploy status. *Target device deployment status.
					Enum:
						'deploying'
						'success'
						'fail'
						'cancel'
				update_progress_percentage : integer
					The update progress in percentage.
				description : string
					The deploy description.
				config_id : string
					The deploy config ID.
				replace_model_id : string
					(Only if "deploy_type"="device_model") The replace model ID.
				replace_network_id : string
					(Only if "deploy_type"="device_model") The replace network ID.
				edge_system_sw_package : object
					firmware_id : string
						The Edge System Software Package firmware ID.
					firmware_version : string
						The Edge System Software Package version.
				models : array
					model_id : string
						The model ID.
					model_version_number : string
						The model version number.
					model_comment : string
						The model comment.
					model_version_comment : string
						The model version comment.
				edge_apps : array
					app_name : string
						The application name.
					app_version : string
						The application version.
					description : string
						The description of the application.
				model_bundles : array
					model_bundle_name : string
						The model bundle name.
					model_bundle_version : string
						The model bundle version.
					description : string
						The description of the model bundle.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0028001
				  Invalid parameter limit.
				- E.SC.API.0028002
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}/deploys', headers=headers, method='GET', device_id=device_id, limit=limit, starting_after=starting_after, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeployHistory(self, limit:int=None, starting_after:str=None, grant_type:str=None):
        """
		Lists the deployment history.

		Parameters:
		------------------------------
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 50
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			deploy_history : array (required)
				deploy_id : string (required)
					Deploy ID.
				from_datetime : string (required)
					Deployment from datetime.
				deploy_type : string (required)
					Deployment Type
					Enum:
						'deploy_config'
						'device_model'
				deploying_cnt : integer (required)
					Returns the deploying cnt.
				success_cnt : integer (required)
					Returns the success cnt.
				fail_cnt : integer (required)
					Returns the fail cnt.
				config_id : string
					Deploy Configuration ID.
				replace_model_id : string
					(Only if "deploy_type"="device_model") The replace model ID.
				replace_network_id : string
					(Only if "deploy_type"="device_model") The replace network ID.
				edge_system_sw_package : object
					firmware_id : string
						The Edge System Software Package firmware ID.
					firmware_version : string
						The Edge System Software Package version.
				models : array
					model_id : string
						The model ID.
					model_version_number : string
						The model version number.
					model_comment : string
						The model comment.
					model_version_comment : string
						The model version comment.
				edge_apps : array
					app_name : string
						The application name.
					app_version : string
						The application version.
					description : string
						The description of the application.
				model_bundles : array
					model_bundle_name : string
						The model bundle name.
					model_bundle_version : string
						The model bundle version.
					description : string
						The description of the model bundle.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0273005
				  Invalid parameter limit.
				- E.SC.API.0273006
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/deploy_history', headers=headers, method='GET', limit=limit, starting_after=starting_after, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeployStatus(self, deploy_id:str, grant_type:str=None):
        """
		Returns the status of specified deployment ID.

		Parameters:
		------------------------------
		deploy_id : str (required) 
			Deployment ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			deploy_id : string (required)
				ID in table sc_t_deploy or sc_t_app_deploy
			from_datetime : string (required)
				Deployment from datetime.
			deploy_type : string (required)
				Deployment Type.
			deploying_cnt : integer
				Returns the running cnt.
			success_cnt : integer (required)
				Returns the success cnt.
			fail_cnt : integer (required)
				Returns the fail cnt.
			config_id : string
				The deploy config ID.
			replace_model_id : string
				(Only if "deploy_type"="device_model") The replace model ID.
			replace_network_id : string
				(Only if "deploy_type"="device_model") The replace network ID.
			edge_system_sw_package : object
				firmware_id : string
					The Edge System Software Package firmware ID.
				firmware_version : string
					The Edge System Software Package version.
			models : array
				model_id : string
					The model ID.
				model_version_number : string
					The model version number.
				model_comment : string
					The model comment.
				model_version_comment : string
					The model version comment.
			edge_apps : array
				app_name : string
					The application name.
				app_version : string
					The application version.
				description : string
					The description of the application.
			model_bundles : array
				model_bundle_name : string
					The model bundle name.
				model_bundle_version : string
					The model bundle version.
				description : string
					The description of the model bundle.
			devices : array (required)
				device_id : string (required)
					The device ID.
				device_name : string (required)
					The device name.
				deploy_status : string (required)
					Get the deploy status. *Target device deployment status.
					Enum:
						'deploying'
						'success'
						'fail'
						'cancel'
				update_progress_percentage : integer
					The update progress in percentage.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0274001  
				  Invalid parameter deploy_type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0274002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/deploy_history/{deploy_id}', headers=headers, method='GET', deploy_id=deploy_id, grant_type=grant_type)
        return ret

    @debug_print
    def DeployDeviceModel(self, model_id:str, device_id:str, version_number:str=None, replace_model_id:str=None, description:str=None, grant_type:str=None):
        """
		Deploys the device model to the specified Edge Device.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		device_id : str (required) 
			Device ID.
		version_number : str
			Version number.
		replace_model_id : str
			Replace model ID.
		description : str
			Description of the subject. The maximum number of characters that can be specified is 100.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0059003  
				  Bad request.  
				- E.SC.API.0059004  
				  Bad request.  
				- E.SC.API.0059006  
				  Bad request.  
				- E.SC.API.0059008  
				  Bad request.  
				- E.SC.API.0059011  
				  Invalid parameter description.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0059010  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0059001  
				  Not found.  
				- E.SC.API.0059002  
				  Not found.  
				- E.SC.API.0059005  
				  Not found.  
				- E.SC.API.0059007  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}/devices/{device_id}/deploy', headers=headers, method='POST', model_id=model_id, device_id=device_id, version_number=version_number, replace_model_id=replace_model_id, description=description, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceGroups(self, limit:int=None, starting_after:str=None, device_group_id:str=None, description:str=None, device_id:str=None, grant_type:str=None):
        """
		Lists the information of registered Edge Devices included in the specified group. By specifying the device ID in the query parameter, you can also verify to which group the device belongs.

		Parameters:
		------------------------------
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 100
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		device_group_id : str
			ID of the device groups. *Fuzzy searching is available.
		description : str
			Description of the subject. *Fuzzy searching is available.
		device_id : str
			Device IDs within the corresponding group.
			Returns a list of device groups that includes the specified device ID.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			device_groups : array (required)
				Provides a list of subordinate elements in ascending order of the device group IDs.
				device_group_id : string
					The device group ID.
				device_type : string
					The device type.
				description : string
					The device group description.
				ins_id : string
					The subject that created the device group.
				ins_date : string
					The date the device group was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				upd_id : string
					The subject that updated the device group.
				upd_date : string
					The date the device group was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				devices : array
					device_id : string
						The device ID.
					property : object
						device_name : string (required)
							The device name.
						internal_device_id : string (required)
							The internal device ID.
					device_type : string
						The device type.
					display_device_type : string
						The display device type.
					place : string
						The location.
					description : string
						The device description.
					ins_id : string
						The subject that registered the device.
					ins_date : string
						The date the device was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
					upd_id : string
						The subject that updated the device.
					upd_date : string
						The date the device was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0031001
				  Invalid parameter limit.
				- E.SC.API.0031002
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devicegroups', headers=headers, method='GET', limit=limit, starting_after=starting_after, device_group_id=device_group_id, description=description, device_id=device_id, grant_type=grant_type)
        return ret

    @debug_print
    def CreateDeviceGroup(self, device_group_id:str, description:str=None, device_id:str=None, del_from_dgroup:str=None, grant_type:str=None):
        """
		Creates a new device group.

		Parameters:
		------------------------------
		device_group_id : str (required) 
			Name of the device group.  
			Group names should be in single-byte characters and the maximum number of characters that can be specified is 100. Half-width commas are not allowed. 
		description : str
			Description of the subject. The maximum number of characters that can be specified is 100.
		device_id : str
			Included device ID.  
			If there are multiple targets: 
			 * use comma separation
			 * avoid using same values
		del_from_dgroup : str
			To remove the device belonging to multiple groups, configure the following:  
			- Value definition:
			  0: Do not delete  
			  1: Delete
			Default value : 0
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0033001  
				  Parameter device_group_id is not set.  
				- E.SC.API.0033002  
				  Invalid parameter device_group_id.  
				- E.SC.API.0033003  
				  Invalid parameter device_type.  
				- E.SC.API.0033004  
				  Invalid parameter device_id.  
				- E.SC.API.0033005  
				  Parameter device_group_id is registered.  
				- E.SC.API.0033009  
				  Invalid parameter del_from_dgroup. 
				- E.SC.API.0033010  
				  Invalid parameter description.   
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0033006  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devicegroups', headers=headers, method='POST', device_group_id=device_group_id, description=description, device_id=device_id, del_from_dgroup=del_from_dgroup, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceGroup(self, device_group_id:str, grant_type:str=None):
        """
		Lists the information for specific device groups (device group ID).

		Parameters:
		------------------------------
		device_group_id : str (required) 
			The name of a device group.
			Group names should be in single-byte characters and be specified within 100 characters. Half-width commas are not allowed. 
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			device_group_id : string
				The device group ID.
			device_type : string
				The device type.
			description : string
				The device group description.
			ins_id : string
				The subject that created the device group.
			ins_date : string
				The date the device group was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			upd_id : string
				The subject that updated the device group.
			upd_date : string
				The date the device group was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			devices : array
				device_id : string
					The device ID.
				property : object
					device_name : string (required)
						The device name.
					internal_device_id : string (required)
						The internal device ID.
				device_type : string
					The device type.
				display_device_type : string
					The display device type.
				place : string
					The location.
				description : string
					The device description.
				ins_id : string
					The subject that registered the device.
				ins_date : string
					The date the device was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				upd_id : string
					The subject that updated the device.
				upd_date : string
					The date the device was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0032001  
				  Not found.  
				- E.SC.API.0032002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devicegroups/{device_group_id}', headers=headers, method='GET', device_group_id=device_group_id, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteDeviceGroup(self, device_group_id:str, grant_type:str=None):
        """
		Deletes the device registration specified by the device_id.

		Parameters:
		------------------------------
		device_group_id : str (required) 
			ID of device group that you want to delete.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0035001  
				  Bad request.  
				- E.SC.API.0035002  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- W.SC.API.0035003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0035004  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devicegroups/{device_group_id}', headers=headers, method='DELETE', device_group_id=device_group_id, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateDeviceGroup(self, device_group_id:str, description:str=None, device_id:str=None, del_from_dgroup:str=None, grant_type:str=None):
        """
		Performs device registration, deletion, and update within the specified device group.

		Parameters:
		------------------------------
		device_group_id : str (required) 
			Name of the device group that you want to update.
		description : str
			Description of the subject. The maximum number of characters that can be specified is 100.  
			To delete the description, specify "@@nullupdate".  
			*An error will occur if description and device_id are not set.
		device_id : str
			The affiliated device ID you want to replace.  
			To disaffiliate the device ID, specify "@@nullupdate".  
			If there are multiple targets: 
			* use comma separation
			* avoid using same values  
			*An error will occur if description and device_id are not set.
		del_from_dgroup : str
			Specify whether or not to disaffiliate the device from the default group.
			- Value definition:  
			  0: Do not delete  
			  1: Delete
			Default value : 0
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0034002  
				  Bad request.  
				- E.SC.API.0034003  
				  Parameter is not set.  
				- E.SC.API.0034008  
				  Bad request.  
				- E.SC.API.0034009  
				  Invalid parameter del_from_dgroup.  
				- E.SC.API.0034010  
				  Invalid parameter description.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0034004  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0034005  
				  Internal server error.  
				- W.SC.API.0034006  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devicegroups/{device_group_id}', headers=headers, method='PATCH', device_group_id=device_group_id, description=description, device_id=device_id, del_from_dgroup=del_from_dgroup, grant_type=grant_type)
        return ret

    @debug_print
    def GetEventLogs(self, device_id:str, limit:int=None, starting_after:str=None, from_datetime:str=None, to_datetime:str=None, grant_type:str=None):
        """
		Returns the event log for a specified Edge Device.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 20
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		from_datetime : str
			Date and time (From).
			- Format: yyyyMMddThhmmss.SSSSSS or yyyy-MM-ddThh:mm:ss.SSSSSS (ISO-8601)
			- The time range between from_datetime and to_datetime must not exceed the retention period.
		to_datetime : str
			Date and time (To).
			- Format: yyyyMMddThhmmss.SSSSSS or yyyy-MM-ddThh:mm:ss.SSSSSS (ISO-8601)
			- It must not be before or equal the value of from_datetime.
			- The time range between from_datetime and to_datetime must not exceed the retention period.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			event_logs : array
				id : string
					The event ID.
				device_id : string
					The device ID.  
				level : string
					The log level.  
					  Example: Warn, Error  
				component : string
					The event component code.  
				error_code : string
					Error code.  
				description : string
					Description of the subject.  
				time : string
					The event time.  
				ingestion_time : string
					The event log time ingested in system.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0194005
				  Invalid parameter limit.
				- E.SC.API.0194006
				  Invalid parameter starting after.
				- E.SC.API.0194007  
				  Invalid parameter from_datetime.
				- E.SC.API.0194008  
				  Invalid parameter to_datetime.  
				- E.SC.API.0213009
				  to_datetime timestamp must not be before or equal to from_datetime
				- E.SC.API.0213010
				  The time range between from_datetime and to_datetime exceeds the retention period.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}/eventlogs', headers=headers, method='GET', device_id=device_id, limit=limit, starting_after=starting_after, from_datetime=from_datetime, to_datetime=to_datetime, grant_type=grant_type)
        return ret

    @debug_print
    def GetEdgeAppLogs(self, device_id:str, limit:int=None, starting_after:str=None, from_datetime:str=None, to_datetime:str=None, grant_type:str=None):
        """
		Returns logs output by the Edge Application on a specific Edge Device.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 50
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		from_datetime : str
			Date and time (From).
			- Format: yyyyMMddThhmmss.SSSSSS or yyyy-MM-ddThh:mm:ss.SSSSSS (ISO-8601)
			- The time range between from_datetime and to_datetime must not exceed the retention period.
		to_datetime : str
			Date and time (To).
			- Format: yyyyMMddThhmmss.SSSSSS or yyyy-MM-ddThh:mm:ss.SSSSSS (ISO-8601)
			- It must not be before or equal the value of from_datetime.
			- The time range between from_datetime and to_datetime must not exceed the retention period.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			logs : array (required)
				id : string
					The log ID.
				log : string
					The log message.
				app : string
					The app instance name.
				stream : string
					The stream type.
				time : string
					The log time.
				ingestion_time : string
					The log time ingested in system.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0213005
				  Invalid parameter limit.
				- E.SC.API.0213006
				  Invalid parameter starting after.
				- E.SC.API.0213007  
				  Invalid parameter from_datetime.
				- E.SC.API.0213008  
				  Invalid parameter to_datetime.
				- E.SC.API.0213009
				  to_datetime timestamp must not be before or equal to from_datetime
				- E.SC.API.0213010
				  The time range between from_datetime and to_datetime exceeds the retention period.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0213004  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/devices/{device_id}/applogs', headers=headers, method='GET', device_id=device_id, limit=limit, starting_after=starting_after, from_datetime=from_datetime, to_datetime=to_datetime, grant_type=grant_type)
        return ret

    @debug_print
    def GetTrainingKits(self, order_by:str=None, grant_type:str=None):
        """
		Returns a list of specific training kit information.

		Parameters:
		------------------------------
		order_by : str
			Sort order: Sorted by the training kit creation date.
			Value range: desc or asc
			Default value : asc
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			training_kits : array (required)
				id : string
					The training kit ID.
				name : string
					The training kit name.
				description : string
					The tag description.
				created_on : string
					The date the training kit was created.
				status : string
					The status.
				training_kit_type : string
					The training kit type.
				default_dataset_split_percentage : number
					The default dataset split percentage.
				framework : object
					name : string
						The framework name.
					version : string
						The framework version.
				owner : string
					The owner.
				is_public : boolean
					Set whether or not to publish.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0159001  
				  Invalid parameter status.  
				- E.SC.API.0159002  
				  Invalid parameter training_kit_type.  
				- E.SC.API.0159003  
				  Invalid parameter order_by.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0159005  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/training_kits', headers=headers, method='GET', order_by=order_by, grant_type=grant_type)
        return ret

    @debug_print
    def GetProjects(self, project_name:str=None, model_platform:str=None, project_type:str=None, device_id:str=None, include_training_flg:str=None, grant_type:str=None):
        """
		Searches and returns projects that match the conditions specified in the parameter. If no parameters are specified, all created projects are returned.

		Parameters:
		------------------------------
		project_name : str
			Name of the project. *Fuzzy searching is available.
		model_platform : str
			Specifies the AI model platform. 
			 - Value definition:  
			   0: Custom Vision  
			   1: Non-Custom Vision
		project_type : str
			Specifies the project type. 
			 - Value definition:  
			   0: Base model  
			   1: Device model  
		device_id : str
			Sorts the device ID.
		include_training_flg : str
			To return the project property, set "true". 
			Default value : 0
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			model_projects : array (required)
				model_project_name : string (required)
					The model project name.
				model_project_id : string (required)
					The model project ID.
				model_platform : string
					The model platform.
				model_type : string
					The model type.
				project_type : string
					The project type.
				device_id : string
					The model device ID.
				project_model_file_name : string
					The project model filename.
				project_model_accuracy : string
					The project model accuracy.
				project_comment : string
					The project comment.
				project : object
					training_kit_id : string
						The training kit ID.
					training_kit_name : string
						The training kit name.
					description : string
						The description of the subject.
					iteration_id : string
						The iteration ID.
					iteration_name : string
						The iteration name.
					last_modified : string
						The last modified.
				model : object
					model_id : string
						The model ID.
					model_type : string
						The device type.
					functionality : string
						The function descriptions.
					vendor_name : string
						The vendor's name.
					model_comment : string
						The description of the subject.
					create_by : string
						Returns the create_by.
						- Value definition:  
						  Self: Self-training models
						  Marketplace: Marketplace purchasing model
					package_id : string
						The marketplace package ID.
					product_id : string
						The marketplace product ID.
					metadata_format_id : string
						The metadata_format_id.
					latest_version : 
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0071001
				  Invalid parameter model_platform.
				- E.SC.API.0071002
				  Invalid parameter project_type.
				- E.SC.API.0071003
				  Invalid parameter include_training_flg.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects', headers=headers, method='GET', project_name=project_name, model_platform=model_platform, project_type=project_type, device_id=device_id, include_training_flg=include_training_flg, grant_type=grant_type)
        return ret

    @debug_print
    def CreateBaseProject(self, project_name:str, training_kit:str, comment:str=None, grant_type:str=None):
        """
		Creates a new project for a base model.

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project. The maximum number of characters that can be specified is 50.
		training_kit : str (required) 
			Specifies the ID of the training kit to use.
		comment : str
			Description of the subject. The maximum number of characters that can be specified is 100.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0044001  
				  Parameter project_name is not set.  
				- E.SC.API.0044002  
				  Invalid parameter project_name.  
				- E.SC.API.0044003  
				  Invalid parameter comment.  
				- E.SC.API.0044004  
				  The specified parameter project_name is registered.  
				- E.SC.API.0044005  
				  Invalid parameter training_kit.  
				- E.SC.API.0044006  
				  Parameter training_kit is not set.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/base', headers=headers, method='POST', project_name=project_name, training_kit=training_kit, comment=comment, grant_type=grant_type)
        return ret

    @debug_print
    def CreateDeviceProject(self, project_name:str, model_id:str, device_id:str, version_number:str=None, comment:str=None, grant_type:str=None):
        """
		Creates a project for the device model by using the specified model's base model.

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project. The maximum number of characters that can be specified is 50.
		model_id : str (required) 
			ID of the AI model.
		device_id : str (required) 
			Sorts the device ID.
		version_number : str
			Version number. The default version is set to the latest one.
		comment : str
			Description of the subject. The maximum number of characters that can be specified is 100.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0046001  
				  Parameter model_id is not set.  
				- E.SC.API.0046002  
				  Parameter device_id is not set.  
				- E.SC.API.0046003  
				  Invalid parameter device_id.  
				- E.SC.API.0046004  
				  Parameter project_name is not set.  
				- E.SC.API.0046005  
				  Invalid parameter project_name.  
				- E.SC.API.0046006  
				  Invalid parameter comment.  
				- E.SC.API.0046007  
				  The specified parameter project_name is registered.  
				- E.SC.API.0046010  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0046008  
				  Not found.  
				- E.SC.API.0046009  
				  Not found.  
				- E.SC.API.0046012  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0046011  
				  Internal server error.  
				- E.SC.API.0046014  
				  Internal server error.  
				- E.SC.API.0046015  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/device', headers=headers, method='POST', project_name=project_name, model_id=model_id, device_id=device_id, version_number=version_number, comment=comment, grant_type=grant_type)
        return ret

    @debug_print
    def GetProject(self, project_name:str, include_training_flg:str=None, grant_type:str=None):
        """
		Returns a list of specific project's information.

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project.
		include_training_flg : str
			To return the project property, set "true". 
			Default value : 0
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			model_project_name : string (required)
				The model project name.
			model_project_id : string (required)
				The model project ID.
			model_platform : string
				The model platform.
			model_type : string
				The model type.
			project_type : string
				The project type.
			device_id : string
				The model device ID.
			project_model_file_name : string
				The project model filename.
			project_model_accuracy : string
				The project model accuracy.
			project_comment : string
				The project comment.
			project : object
				training_kit_id : string
					The training kit ID.
				training_kit_name : string
					The training kit name.
				description : string
					The description of the subject.
				iteration_id : string
					The iteration ID.
				iteration_name : string
					The iteration name.
				last_modified : string
					The last modified.
			model : object
				model_id : string
					The model ID.
				model_type : string
					The device type.
				functionality : string
					The function descriptions.
				vendor_name : string
					The vendor's name.
				model_comment : string
					The description of the subject.
				create_by : string
					Returns the create_by.
					- Value definition:  
					  Self: Self-training models
					  Marketplace: Marketplace purchasing model
				package_id : string
					The marketplace package ID.
				product_id : string
					The marketplace product ID.
				metadata_format_id : string
					The metadata_format_id.
				latest_version : 
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0054001  
				  Not found.  
				- E.SC.API.0054002  
				  Invalid parameter include_training_flg.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_name}', headers=headers, method='GET', project_name=project_name, include_training_flg=include_training_flg, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteProject(self, project_name:str, grant_type:str=None):
        """
		Deletes the created model. 
		*To delete a model in process of creation, use DeleteModel instead.

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0079004  
				  Bad request.  
				- W.SC.API.0079005  
				  Since preparations for deletion have not been completed  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0079003  
				  Not found.  
				- W.SC.API.0079001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_name}', headers=headers, method='DELETE', project_name=project_name, grant_type=grant_type)
        return ret

    @debug_print
    def SaveModel(self, project_name:str, model_id:str=None, initial_version_number:int=None, functionality:str=None, vendor_name:str=None, comment:str=None, grant_type:str=None):
        """
		Saves the pre-converted model (projects of base model or device model).

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project.
		model_id : str
			ID of the AI model. The maximum number of characters that can be specified is 20 single-byte ones. 
			*Available only when registering a new base model.
		initial_version_number : int
			An initial version number of the AI model to be saved. 
			*Available only when registering a new base model.
			- Value range: 1 to 99  
			Default value : 1
		functionality : str
			Description of the functionality. The maximum number of characters that can be specified is 100. 
			*Available only when registering a new base model.
		vendor_name : str
			Name of the vendor. The maximum number of characters that can be specified is 100. 
			*Available only when registering a new base model.
		comment : str
			Description of the subject. The maximum number of characters that can be specified is 100. 
			*If the description is saved for the first time, it will be applied for both model and its version. 
			*When updating the content, it will be registered as a description for the version. 
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0045001  
				  Parameter model_id is not set.  
				- E.SC.API.0045002  
				  Invalid parameter model_id.  
				- E.SC.API.0045003  
				  Invalid parameter initial_version_number.  
				- E.SC.API.0045004  
				  Invalid parameter functionality.  
				- E.SC.API.0045005  
				  Invalid parameter vendor_name.  
				- E.SC.API.0045006  
				  Invalid parameter comment.  
				- E.SC.API.0045008  
				  The specified parameter model_id is registered.  
				- E.SC.API.0045009  
				  Bad request.  
				- E.SC.API.0045014  
				  Bad request.  
				- E.SC.API.0045015  
				  Bad request.  
				- E.SC.API.0045018  
				  Bad request.  
				- E.SC.API.0045019  
				  Bad request.  
				- E.SC.API.0045020  
				  Bad request.  
				- E.SC.API.0045021  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0045022  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0045007  
				  Not found.  
				- E.SC.API.0045011  
				  Not found.  
				- E.SC.API.0045013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000017  
				  Too many requests for the Re-learning Service. Please run it again after a while.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0045016  
				  Internal server error.  
				- E.SC.API.0045017  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_name}/save', headers=headers, method='POST', project_name=project_name, model_id=model_id, initial_version_number=initial_version_number, functionality=functionality, vendor_name=vendor_name, comment=comment, grant_type=grant_type)
        return ret

    @debug_print
    def GetRelearnStatus(self, project_name:str, grant_type:str=None):
        """
		The retraining status of a specific model.

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
			status : string
				The retraining status. 
				- Value definition:  
				Training  
				Completed
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0075001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_name}/relearn', headers=headers, method='GET', project_name=project_name, grant_type=grant_type)
        return ret

    @debug_print
    def Relearn(self, project_name:str, training_type:str=None, reserved_budget_in_hours:str=None, grant_type:str=None):
        """
		Performs retraining to the specified project.

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project.
		training_type : str
			Training type. *Available only for Custom Vision projects.
			- Value definition:  
			  Regular: Facilitates rapid completion of the training. 
			  Advanced: Increases the accuracy by specifying the training hours with reserved_budget_in_hours parameter.
			Default value : Regular
		reserved_budget_in_hours : str
			The duration time to perform the retraining on Custom Vision projects. *This parameter is available when training_type is set to Advanced.
			Default value : 1
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
			iteration_id : string
				The iteration ID.
			iteration_name : string
				The iteration name.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0074002  
				  Bad request.  
				- E.SC.API.0074003  
				  Invalid parameter training_type.  
				- E.SC.API.0074004  
				  Invalid parameter reserved_budget_in_hours.  
				- E.SC.API.0074006  
				  Invalid parameter epochs.  
				- E.SC.API.0074010  
				  Not enough tags for training.  
				- E.SC.API.0074011  
				  Not enough images per tag for training. It is necessary to set 15 or more images for each tag.  
				- E.SC.API.0074012  
				  Not enough images per tag for training.  
				- E.SC.API.0074013  
				  Not enough images for training.  
				- E.SC.API.0074014  
				  One image cannot be set in multiple tags for Sts {0} project.  
				- E.SC.API.0074015  
				  Training not needed  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0074009  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0074001  
				  Not found.  
				- E.SC.API.0074005  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[409] Conflict:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0074008  
				  Training has already started for the project.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0074007  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_name}/relearn', headers=headers, method='POST', project_name=project_name, training_type=training_type, reserved_budget_in_hours=reserved_budget_in_hours, grant_type=grant_type)
        return ret

    @debug_print
    def ImportImagesFromFiles(self, project_name:str, payload, grant_type:str=None):
        """
		Imports images into your project for retraining purposes.

		Parameters:
		------------------------------
		project_name : str (required) 
			Name of the project.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		images : array (required)
			file_name : string
				The filename.
			contents : string
				The image file (base64 encoding).
		tags_name : array
			The annotation label. *Available only for classification. Supports only 1 tag.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0065001  
				  Json format is invalid.  
				- E.SC.API.0065003  
				  The project is only used for import_dataset_file API.  
				- E.SC.API.0065004  
				  Image format contains invalid files.  
				- E.SC.API.0065005  
				  Image format contains invalid files.  
				- E.SC.API.0065008  
				  The specified functionality of training_kit_type [{0}] is not yet implemented.  
				- W.SC.API.0065006  
				  The import was successful. But I skipped over the invalid images.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0065002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/model_projects/{project_name}/images/files', headers=headers, method='POST', project_name=project_name, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def ImportImagesFromScblob(self, project_name:str, payload, grant_type:str=None):
        """
		Imports images into your project from Azure Blob Storage for retraining purposes.

		Parameters:
		------------------------------
		project_name : str (required) 
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		container_url : string (required)
			The SAS URL of Blob Storage Container. *Read and List permissions required.
		tags_name : array
			The annotation label. *Available only for classification. Supports only 1 tag.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0064001  
				  Json format is invalid.  
				- E.SC.API.0064004  
				  Image format contains invalid files.  
				- E.SC.API.0064005  
				  The specified parameter container_url is not set.  
				- E.SC.API.0064006  
				  The specified URL is invalid.  
				- E.SC.API.0064008  
				  The project is only used for import_dataset_file API.  
				- E.SC.API.0064009  
				  The specified functionality of training_kit_type [{0}] is not yet implemented.  
				- W.SC.API.0064007  
				  The import was successful. But I skipped over the invalid images.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0064002  
				  Not found.  
				- E.SC.API.0064003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/model_projects/{project_name}/images/scbloburls', headers=headers, method='POST', project_name=project_name, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetProjectIterations(self, project_id:str, overlap_threshold:str=None, threshold:str=None, grant_type:str=None):
        """
		Returns a list of specified project's iteration information.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		overlap_threshold : str
			The bounding box overlap threshold used to determine true predictions.
			Default value : 0.3
		threshold : str
			The threshold used to determine true predictions.
			Default value : 0.5
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			iterations : array (required)
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0129003  
				  Invalid parameter thresholds.  
				- E.SC.API.0129004  
				  Invalid parameter overlap_threshold.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0129001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0129002  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/iterations', headers=headers, method='GET', project_id=project_id, overlap_threshold=overlap_threshold, threshold=threshold, grant_type=grant_type)
        return ret

    @debug_print
    def GetProjectImages(self, project_id:str, iteration_id:str=None, order_by:str=None, number_of_images:int=None, skip:int=None, image_size_type:str=None, grant_type:str=None):
        """
		The images registered in a specified project and their information.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		iteration_id : str
			ID of the iteration.
		order_by : str
			Sort order: Sorted by the creation date of the image.
			Value range: newest, oldest  
			Default value : newest
		number_of_images : int
			The number of images to acquire information. 
			Value range: 0 to 256
			Default value : 50
		skip : int
			The number of images to skip acquiring information.
			Default value : 0
		image_size_type : str
			Types of image sizes. *Available only for Custom Vision projects.
			- Value definition:  
			  resized  
			  thumbnail  
			  original
			Default value : resized
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			total_image_count : integer (required)
				The total number of images.
			images : array (required)
				id : string
					The image ID.
				created : string
					The date of creation.
				width : integer
					The width of the image.
				height : integer
					The height of the image.
				image : string
					Returns a base64-encoded image file.
				tags : array
					tag_id : string
						The tag ID.
					tag_name : string
						The name of the tag.
					created : string
						The date of creation.
				regions : array
					region_id : string
						The region ID.
					tag_id : string
						The tag ID.
					tag_name : string
						The name of the tag.
					created : string
						The date of creation.
					left : number
						Left of the region (ratio of image size). *Available only for object detection.
					top : number
						Top of the region (ratio of image size). *Available only for object detection.
					width : number
						Width of the region (ratio of image size). *Available only for object detection.
					height : number
						Height of the region (ratio of image size). *Available only for object detection.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0119001  
				  Invalid parameter order_by.  
				- E.SC.API.0119002  
				  Bad request.  
				- E.SC.API.0119003  
				  Bad request.  
				- E.SC.API.0119007  
				  Invalid parameter image_size_type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0119004  
				  Not found.  
				- E.SC.API.0119005  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0119006  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/images', headers=headers, method='GET', project_id=project_id, iteration_id=iteration_id, order_by=order_by, number_of_images=number_of_images, skip=skip, image_size_type=image_size_type, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteProjectImages(self, project_id:str, image_ids:str, grant_type:str=None):
        """
		Deletes an image specified by its ID from the project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		image_ids : str (required) 
			ID of images. *If you have multiple entries, separate them with commas. IDs can be specified from 1 to 256.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0121001  
				  Parameter image_ids is not set.  
				- E.SC.API.0121002  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0121003  
				  Not found.  
				- W.SC.API.0121005  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0121004  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/images', headers=headers, method='DELETE', project_id=project_id, image_ids=image_ids, grant_type=grant_type)
        return ret

    @debug_print
    def GetProjectImagesById(self, project_id:str, image_ids:str, iteration_id:str=None, image_size_type:str=None, grant_type:str=None):
        """
		Returns a list of information for selected image IDs within a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		image_ids : str (required) 
			ID of images. *If you have multiple entries, separate them with commas. IDs can be specified from 1 to 256.
		iteration_id : str
			ID of the iteration.
		image_size_type : str
			Types of image sizes. *Available only for Custom Vision projects.
			- Value definition:  
			  resized  
			  thumbnail  
			  original
			Default value : resized
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			images : array (required)
				id : string
					The image ID.
				created : string
					The date of creation.
				width : integer
					The width of the image.
				height : integer
					The height of the image.
				image : string
					Returns a base64-encoded image file.
				tags : array
					tag_id : string
						The tag ID.
					tag_name : string
						The name of the tag.
					created : string
						The date of creation.
				regions : array
					region_id : string
						The region ID.
					tag_id : string
						The tag ID.
					tag_name : string
						The name of the tag.
					created : string
						The date of creation.
					left : number
						Left of the region (ratio of image size). *Available only for object detection.
					top : number
						Top of the region (ratio of image size). *Available only for object detection.
					width : number
						Width of the region (ratio of image size). *Available only for object detection.
					height : number
						Height of the region (ratio of image size). *Available only for object detection.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0120001  
				  Parameter image_ids is not set.  
				- E.SC.API.0120002  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0120003  
				  Not found.  
				- E.SC.API.0120004  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0120005  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/images/id', headers=headers, method='GET', project_id=project_id, image_ids=image_ids, iteration_id=iteration_id, image_size_type=image_size_type, grant_type=grant_type)
        return ret

    @debug_print
    def GetImageRegionProposals(self, project_id:str, image_id:str, grant_type:str=None):
        """
		Returns region proposals (inference result) for an image detection along with the specified image ID.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		image_id : str (required) 
			ID of the image.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			project_id : string (required)
				The project ID.
			image_id : string (required)
				The image ID.
			proposals : array (required)
				confidence : string (required)
					The confidence score.
				bounding_box : object (required)
					left : number
						Left of the region (ratio of image size). *Available only for object detection.
					top : number
						Top of the region (ratio of image size). *Available only for object detection.
					width : number
						Width of the region (ratio of image size). *Available only for object detection.
					height : number
						Height of the region (ratio of image size). *Available only for object detection.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0164001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000017  
				  Too many requests for the Re-learning Service. Please run it again after a while.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0164003  
				  Internal server error.  
				- E.SC.API.0164004  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/images/{image_id}/regionproposals', headers=headers, method='GET', project_id=project_id, image_id=image_id, grant_type=grant_type)
        return ret

    @debug_print
    def CreateProjectImageRegions(self, project_id:str, payload, grant_type:str=None):
        """
		Adds a tag to an image within a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		regions : array
			image_id : string (required)
				Image ID.
			tag_id : string
				Tag Id. *Specify when assigning an existing tag.
			tag_name : string
				Tag Name. *Specify when assigning a new tag.
			left : string
				Left of the region (ratio of image size). *Available only for object detection.
			top : string
				Top of the region (ratio of image size). *Available only for object detection.
			width : string
				Width of the region (ratio of image size). *Available only for object detection.
			height : string
				Height of the region (ratio of image size). *Available only for object detection.

		Returns:
		------------------------------
		[200] Successful Response:
			created : array (required)
				region_id : string
					The region ID.
				tag_id : string
					The tag ID.
				tag_name : string
					The name of the tag.
				created : string
					The date of creation.
				left : number
					Left of the region (ratio of image size). *Available only for object detection.
				top : number
					Top of the region (ratio of image size). *Available only for object detection.
				width : number
					Width of the region (ratio of image size). *Available only for object detection.
				height : number
					Height of the region (ratio of image size). *Available only for object detection.
			duplicated : array
				region_id : string
					The region ID.
				tag_id : string
					The tag ID.
				tag_name : string
					The name of the tag.
				created : string
					The date of creation.
				left : number
					Left of the region (ratio of image size). *Available only for object detection.
				top : number
					Top of the region (ratio of image size). *Available only for object detection.
				width : number
					Width of the region (ratio of image size). *Available only for object detection.
				height : number
					Height of the region (ratio of image size). *Available only for object detection.
			exceeded : array
				region_id : string
					The region ID.
				tag_id : string
					The tag ID.
				tag_name : string
					The name of the tag.
				created : string
					The date of creation.
				left : number
					Left of the region (ratio of image size). *Available only for object detection.
				top : number
					Top of the region (ratio of image size). *Available only for object detection.
				width : number
					Width of the region (ratio of image size). *Available only for object detection.
				height : number
					Height of the region (ratio of image size). *Available only for object detection.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0126001  
				  Json format is invalid.  
				- E.SC.API.0126002  
				  Parameter image_id is not set.  
				- E.SC.API.0126003  
				  Parameter tag_id or tag_name is not set.  
				- E.SC.API.0126004  
				  Parameter left is not set.  
				- E.SC.API.0126005  
				  Parameter top is not set.  
				- E.SC.API.0126006  
				  Parameter width is not set.  
				- E.SC.API.0126007  
				  Parameter height is not set.  
				- E.SC.API.0126008  
				  Invalid parameter left.  
				- E.SC.API.0126009  
				  Invalid parameter top.  
				- E.SC.API.0126010  
				  Invalid parameter width.  
				- E.SC.API.0126011  
				  Invalid parameter height.  
				- E.SC.API.0126012  
				  Bad request.  
				- E.SC.API.0126013  
				  Bad request.  
				- E.SC.API.0126018  
				  Invalid Parameter tag_id.  
				- E.SC.API.0126019  
				  Invalid Parameter tag_name.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0126014  
				  Not found.  
				- E.SC.API.0126015  
				  Not found.  
				- E.SC.API.0126016  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000017  
				  Too many requests for the Re-learning Service. Please run it again after a while.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0126017  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/model_projects/{project_id}/images/regions', headers=headers, method='POST', project_id=project_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateProjectImageRegions(self, project_id:str, payload, grant_type:str=None):
        """
		Updates tags applied to images within a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			Description of the subject.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		regions : array
			image_id : string (required)
				Image ID.
			tag_id : string
				Tag Id. *Specify when assigning an existing tag.
			tag_name : string
				Tag Name. *Specify when assigning a new tag.
			left : string
				Left of the region (ratio of image size). *Available only for object detection.
			top : string
				Top of the region (ratio of image size). *Available only for object detection.
			width : string
				Width of the region (ratio of image size). *Available only for object detection.
			height : string
				Height of the region (ratio of image size). *Available only for object detection.

		Returns:
		------------------------------
		[200] Successful Response:
			updated : array
				region_id : string
					The region ID.
				tag_id : string
					The tag ID.
				tag_name : string
					The name of the tag.
				created : string
					The date of creation.
				left : number
					Left of the region (ratio of image size). *Available only for object detection.
				top : number
					Top of the region (ratio of image size). *Available only for object detection.
				width : number
					Width of the region (ratio of image size). *Available only for object detection.
				height : number
					Height of the region (ratio of image size). *Available only for object detection.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0128001  
				  Json format is invalid.  
				- E.SC.API.0128002  
				  Parameter region_id is not set.  
				- E.SC.API.0128003  
				  Parameter image_id is not set.  
				- E.SC.API.0128004  
				  Parameter tag_id or tag_name is not set.  
				- E.SC.API.0128005  
				  Parameter left is not set.  
				- E.SC.API.0128006  
				  Parameter top is not set.  
				- E.SC.API.0128007  
				  Parameter width is not set.  
				- E.SC.API.0128008  
				  Parameter height is not set.  
				- E.SC.API.0128009  
				  Invalid parameter left.  
				- E.SC.API.0128010  
				  Invalid parameter top.  
				- E.SC.API.0128011  
				  Invalid parameter width.  
				- E.SC.API.0128012  
				  Invalid parameter height.  
				- E.SC.API.0128013  
				  Bad request.  
				- E.SC.API.0128014  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0128015  
				  Not found.  
				- E.SC.API.0128016  
				  Not found.  
				- E.SC.API.0128017  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000017  
				  Too many requests for the Re-learning Service. Please run it again after a while.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0128018  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/model_projects/{project_id}/images/regions', headers=headers, method='PATCH', project_id=project_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteProjectImageRegions(self, project_id:str, region_id:str, grant_type:str=None):
        """
		Removes tags from images within a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		region_id : str (required) 
			ID of the region.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0127001  
				  Not found.  
				- W.SC.API.0127003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0127002  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/images/regions/{region_id}', headers=headers, method='DELETE', project_id=project_id, region_id=region_id, grant_type=grant_type)
        return ret

    @debug_print
    def GetProjectTags(self, project_id:str, iteration_id:str=None, order_by:str=None, grant_type:str=None):
        """
		Returns a list of tags applied to a specific project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		iteration_id : str
			ID of the iteration.
		order_by : str
			Sort order: Sorted by the creation date of the tag.
			Value range: asc, desc  
			Default value : asc
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			tags : array (required)
				tag_id : string
					The tag ID.
				tag_name : string
					The name of the tag.
				tag_description : string
					The tag description.
				tag_type : number
					The tag type.
				image_count : number
					The number of tagged images.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0169001  
				  Bad request.  
				- E.SC.API.0169003  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0169002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/tags', headers=headers, method='GET', project_id=project_id, iteration_id=iteration_id, order_by=order_by, grant_type=grant_type)
        return ret

    @debug_print
    def CreateProjectTag(self, project_id:str, tag_name:str, description:str=None, grant_type:str=None):
        """
		Creates a new tag to a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		tag_name : str (required) 
			The name of the tag.
		description : str
			Description of the subject.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			id : string
				The project ID.
			name : string
				The name of the tag.
			description : string
				The description of the subject.
			type : string
				The type of the subject.
			image_count : string
				The number of tagged images.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0122001  
				  Parameter tag_name is not set.  
				- E.SC.API.0122002  
				  Invalid parameter type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0122003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0122004  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/tags', headers=headers, method='POST', project_id=project_id, tag_name=tag_name, description=description, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteProjectTag(self, project_id:str, tag_id:str, grant_type:str=None):
        """
		Removes tags from a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		tag_id : str (required) 
			ID of the tag.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0124001  
				  Not found.  
				- W.SC.API.0124002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0124003  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/tags/{tag_id}', headers=headers, method='DELETE', project_id=project_id, tag_id=tag_id, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateProjectTag(self, project_id:str, tag_id:str, payload, grant_type:str=None):
        """
		Updates tags applied to a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		tag_id : str (required) 
			ID of the tag.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		name : string (required)
			Name.
		description : string
			Description of the subject.
		type : string (required)
			type. *Specify Regular as fixed.

		Returns:
		------------------------------
		[200] Successful Response:
			id : string
				The project ID.
			name : string
				The name of the tag.
			description : string
				The description of the subject.
			type : string
				The type of the subject.
			image_count : string
				The number of tagged images.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0123001  
				  Json format is invalid.  
				- E.SC.API.0123002  
				  Parameter tag name to be updated is not set.  
				- E.SC.API.0123003  
				  Parameter tag description to be updated is not set.  
				- E.SC.API.0123004  
				  Parameter tag type to be updated is not set.  
				- E.SC.API.0123005  
				  Invalid parameter tag type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0123006  
				  Not found.  
				- W.SC.API.0123007  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0123008  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/model_projects/{project_id}/tags/{tag_id}', headers=headers, method='PATCH', project_id=project_id, tag_id=tag_id, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetProjectTaggedImages(self, project_id:str, tag_ids:str=None, iteration_id:str=None, number_of_images:int=None, skip:int=None, order_by:str=None, image_size_type:str=None, grant_type:str=None):
        """
		Returns information of tagged images within a specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		tag_ids : str
			ID of tags. *If you have multiple entries, separate them with commas.
		iteration_id : str
			ID of the iteration.
		number_of_images : int
			The number of images to acquire information. 
			Value range: 0 to 256
			Default value : 50
		skip : int
			The number of images to skip acquiring information.
			Default value : 0
		order_by : str
			Sort order: Sorted by the creation date of the image.
			Value range: newest, oldest
			Default value : newest
		image_size_type : str
			Types of image sizes. *Available only for Custom Vision projects.
			- Value definition:  
			  resized  
			  thumbnail  
			  original
			Default value : resized
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			total_image_count : integer (required)
				The total number of images.
			tagged_images : array (required)
				id : string
					The image ID.
				created : string
					The date of creation.
				width : integer
					The width of the image.
				height : integer
					The height of the image.
				image : string
					Returns a base64-encoded image file.
				tags : array
					tag_id : string
						The tag ID.
					tag_name : string
						The name of the tag.
					created : string
						The date of creation.
				regions : array
					region_id : string
						The region ID.
					tag_id : string
						The tag ID.
					tag_name : string
						The name of the tag.
					created : string
						The date of creation.
					left : number
						Left of the region (ratio of image size). *Available only for object detection.
					top : number
						Top of the region (ratio of image size). *Available only for object detection.
					width : number
						Width of the region (ratio of image size). *Available only for object detection.
					height : number
						Height of the region (ratio of image size). *Available only for object detection.
			blank_tags : array
				tag_id : string
					ID of the tag.
				tag_name : string
					The name of the tag.
				description : string
					The description of the subject.
				type : string
					The type of the subject.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0125001  
				  Bad request.  
				- E.SC.API.0125002  
				  Bad request.  
				- E.SC.API.0125003  
				  Bad request.  
				- E.SC.API.0125004  
				  Invalid parameter order_by.  
				- E.SC.API.0125008  
				  Invalid parameter image_size_type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0125005  
				  Not found.  
				- E.SC.API.0125006  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0125007  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/tags/tagged_images', headers=headers, method='GET', project_id=project_id, tag_ids=tag_ids, iteration_id=iteration_id, number_of_images=number_of_images, skip=skip, order_by=order_by, image_size_type=image_size_type, grant_type=grant_type)
        return ret

    @debug_print
    def GetProjectUntaggedImages(self, project_id:str, iteration_id:str=None, number_of_images:int=None, skip:int=None, order_by:str=None, image_size_type:str=None, grant_type:str=None):
        """
		Returns information of untagged images within the specified project.

		Parameters:
		------------------------------
		project_id : str (required) 
			ID of the project.
		iteration_id : str
			ID of the iteration.
		number_of_images : int
			The number of images to acquire information. 
			Value range: 0 to 256
			Default value : 50
		skip : int
			The number of images to skip acquiring information.
			Default value : 0
		order_by : str
			Sort order: Sorted by the creation date of the image.
			Value range: newest, oldest
			Default value : newest
		image_size_type : str
			Types of image sizes. *Available only for Custom Vision projects.
			- Value definition:  
			  resized  
			  thumbnail  
			  original
			Default value : resized
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			total_image_count : integer (required)
				The total number of images.
			untagged_images : array
				id : string
					The image ID.
				created : string
					The date of creation.
				width : integer
					The width of the image.
				height : integer
					The height of the image.
				image : string
					Returns a base64-encoded image file.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0136001  
				  Bad request.  
				- E.SC.API.0136002  
				  Bad request.  
				- E.SC.API.0136003  
				  Invalid parameter order_by.  
				- E.SC.API.0136007  
				  Invalid parameter image_size_type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0136004  
				  Not found.  
				- E.SC.API.0136005  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0136006  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_projects/{project_id}/tags/untagged_images', headers=headers, method='GET', project_id=project_id, iteration_id=iteration_id, number_of_images=number_of_images, skip=skip, order_by=order_by, image_size_type=image_size_type, grant_type=grant_type)
        return ret

    @debug_print
    def GetModels(self, limit:int=None, starting_after:str=None, model_id:str=None, comment:str=None, project_name:str=None, model_platform:str=None, project_type:str=None, device_id:str=None, latest_type:str=None, grant_type:str=None):
        """
		Returns a list of model information.

		Parameters:
		------------------------------
		limit : int
			Number of Models to fetch.
			Value range: 1 to 256
			Default value : 50
		starting_after : str
			A token to use in pagination. starting_after is an object ID that defines your place in the list. For example, if you make a list request and receive 100 objects, ending with obj_foo, your subsequent call can include starting_after=obj_foo to fetch the next page of the list.
		model_id : str
			ID of the AI model. *Fuzzy searching is available.
		comment : str
			Description of the subject. *Fuzzy searching is available.
		project_name : str
			Name of the project. *Fuzzy searching is available.
		model_platform : str
			Specifies the AI model platform. 
			- Value definition:  
			  0: Custom Vision  
			  1: Non-Custom Vision
		project_type : str
			Specifies the project type. 
			- Value definition:  
			  0: Base model  
			  1: Device model  
		device_id : str
			Sorts the device ID.
		latest_type : str
			Classification of the latest version. 
			- Value definition:  
			  0: Latest version after publication.  
			  1: Latest version after completion of the conversion process or publication.
			Default value : 1
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			models : array (required)
				model_id : string
					The model ID.
				model_type : string
					The model type.
				functionality : string
					The function descriptions.
				vendor_name : string
					The vendor's name.
				model_comment : string
					The description of the subject.
				network_type : string
					The network type.
				create_by : string
					Returns the create_by.
					- Value definition:  
					  Self: Self-training models
					  Marketplace: Marketplace purchasing model
				package_id : string
					The marketplace package ID.
				product_id : string
					The marketplace product ID.
				metadata_format_id : string
					The metadata_format_id.
				projects : array
					model_project_name : string
						The model project name.
					model_project_id : string
						The model project ID.
					model_platform : string
						The model platform.
					model_type : string
						The model type.
					project_type : string
						The project type.
					device_id : string
						The device ID.
					versions : array
						There must be one subordinate element for this API.
						version_number : string
							The version number.
						iteration_id : string
							The iteration ID.
						iteration_name : string
							The iteration name.
						accuracy : string
							The accuracy.
						model_performances : object
							The performance information of the AI model.
						latest_flg : string
							The latest flag.
						publish_latest_flg : string
							The latest published flag.
						version_status : string
							The status.
						org_file_name : string
							The pre-conversion model filename.
						org_file_size : integer
							The publish model file size.
						publish_file_name : string
							The publish model filename.
						publish_file_size : integer
							The publish model file size.
						model_file_size : integer
							The model file size.
						model_framework : string
							The model framework.
						conv_id : string
							The conversion request ID.
						labels : array
							The label array.
						stage : string
							The conversion stage.
						result : string
							The conversion result.
						kpi : object
			continuation_token : string (required)
				Last token of extracted data. Empty if there is no next data.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0056001
				  Invalid parameter model_platform.
				- E.SC.API.0056002
				  Invalid parameter project_type.
				- E.SC.API.0056003
				  Invalid parameter latest_type.
				- E.SC.API.0056004
				  Invalid parameter limit.
				- E.SC.API.0056005
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models', headers=headers, method='GET', limit=limit, starting_after=starting_after, model_id=model_id, comment=comment, project_name=project_name, model_platform=model_platform, project_type=project_type, device_id=device_id, latest_type=latest_type, grant_type=grant_type)
        return ret

    @debug_print
    def ImportBaseModel(self, payload, grant_type:str=None):
        """
		Imports a base model into your project. When registering a new model ID, it will be added accordingly. Specifying an existing ID will result in overwriting.

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		<One of type : InputFileUrlOfImportBaseModelJsonBody>
			model : string (required)
				SAS URL or Presigned URL of the AI model file.
			input_format_param : string
				SAS URL or Presigned URL of the input format param file.
				*Usage: Packager conversion information (image format information).  
				*The json format is an array of objects. Each object contains the following values.  
				 ・ordinal: Order of DNN input to converter (value range: 0 to 2)  
				 ・format: Format ("RGB" or "BGR")  
				*Example:  
				 [{  
				     "ordinal": 0,  
				     "format": "RGB"  
				 },  
				 {  
				     "ordinal": 1,  
				     "format": "RGB"  
				 }]  
			network_config : string
				SAS URL or Presigned URL of the network config file.  
				*Usage: Conversion parameter information of the model converter. Therefore, it is not necessary to specify when specifying the AI model before conversion.  
				*Example:  
				 {  
				   "Postprocessor": {  
				     "params": {  
				       "background": false,  
				       "scale_factors": [  
				         10.0,  
				         10.0,  
				         5.0,  
				         5.0  
				       ],  
				       "score_thresh": 0.01,  
				       "max_size_per_class": 64,  
				       "max_total_size": 64,  
				       "clip_window": [  
				         0,  
				         0,  
				         1,  
				         1  
				       ],  
				       "iou_threshold": 0.45  
				     }  
				   }  
				 }  
			dcpu_firmware_url : string
				SAS URL or Presigned URL of the DCPU FW file.
			dcpu_manifest_url : string
				SAS URL or Presigned URL of the DCPU Manifest file.
			dcpu_postprocess_url : string
				SAS URL or Presigned URL of the DCPU Post Process file.
		<One of type : InputFileIdOfImportBaseModelJsonBody>
			model_file_id : string (required)
				ID of the AI model file.
			input_format_param_file_id : string
				ID of the input format param file.
			network_config_file_id : string
				ID of the network config file.
			dcpu_firmware_file_id : string
				ID of the DCPU FW file.
			dcpu_manifest_file_id : string
				ID of the DCPU Manifest file.
			dcpu_postprocess_file_id : string
				ID of the DCPU Post Process file.
		model_id : string (required)
			Model ID for new registration or version upgrade. The maximum number of characters that can be specified is 100.
		converted : boolean
			Specify whether to convert the specified model file.
		vendor_name : string
			Name of the vendor. The maximum number of characters that can be specified is 100. 
			*Available only when registering a new base model.
		comment : string
			Description of the subject. The maximum number of characters that can be specified is 100. 
			*If the description is saved for the first time, it will be applied for both model and its version. 
			*When updating the content, it will be registered as a description for the version. 
		network_type : string
			Specify whether or not application is required for the AI model. 
			- Value definition:  
			  0: Model required application  
			  1: Model do not required application  
		reserved_mem : integer
			Amount of the reserved memory on the chip when convert the specified model file. (bytes)  
		metadata_format_id : string
			The metadata format ID returned in the response from the UploadFile API. The maximum number of characters that can be specified is 100.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0047001  
				  Json format is invalid.  
				- E.SC.API.0047002  
				  Parameter model_id is not set.  
				- E.SC.API.0047003  
				  Invalid parameter model_id.  
				- E.SC.API.0047005  
				  Neither of  parameter model_list and model_file_id_list is set.  
				- E.SC.API.0047008  
				  Invalid parameter vendor_name.  
				- E.SC.API.0047009  
				  Invalid parameter comment.  
				- E.SC.API.0047010  
				  Bad request.  
				- E.SC.API.0047016  
				  Bad request.  
				- E.SC.API.0047017  
				  Invalid parameter converted.  
				- E.SC.API.0047018  
				  Invalid parameter network_type.  
				- E.SC.API.0047019  
				  Invalid parameter labels.  
				- E.SC.API.0047020  
				  Invalid parameter model_list.  
				- E.SC.API.0047021  
				  Invalid parameter input_format_param or input_format_param_file_id.  
				- E.SC.API.0047022  
				  Invalid parameter network_config or network_config_file_id.  
				- E.SC.API.0047024  
				  Bad request.  
				- E.SC.API.0047026  
				  Invalid parameter model_file_id_list.  
				- E.SC.API.0047027  
				  Invalid parameter model_platform.  
				- E.SC.API.0047029  
				  Only one model file allowed when converted is True.  
				- E.SC.API.0047032  
				  Invalid model file format.  
				- E.SC.API.0047033  
				  Invalid parameter dcpu_firmware_url.  
				- E.SC.API.0047034  
				  Invalid parameter dcpu_manifest_url.  
				- E.SC.API.0047035  
				  Invalid parameter dcpu_postprocess_url.  
				- E.SC.API.0047036  
				  Invalid parameter dcpu files  
				- E.SC.API.0047037  
				  Invalid parameter reserved_mem.  
				- E.SC.API.0047038  
				  The model file exceed size limit.  
				- E.SC.API.0047039  
				  The components of import file is incorrect.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0047030  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0047015  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0047011  
				  Internal server error.  
				- E.SC.API.0047012  
				  Internal server error.  
				- E.SC.API.0047013  
				  Internal server error.  
				- E.SC.API.0047014  
				  Internal server error.  
				- E.SC.API.0047023  
				  Internal server error.  
				- E.SC.API.0047025  
				  Get converter version failed.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/models', headers=headers, method='POST', payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def PublishModel(self, model_id:str, device_id:str=None, grant_type:str=None):
        """
		Converts the AI model.
		This process is handled asynchronously due to its time-consuming nature. 
		*To check the processing status, refer to the result of GetBaseModelStatus API or the response from GetDeviceModelStatus API. When the process is completed, 'Import completed' is returned.

		Parameters:
		------------------------------
		model_id : str (required) 
			A unique ID of the AI model.
		device_id : str
			Device ID  
			*Only available for device models. 
			This parameter is only available for deploying base models.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string
				SUCCESS or WARNING.
			import_id : string
				The conversion request ID (conv_id).
			code : string
				Error code.
			message : string
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- W.SC.API.0181006  
				  The version of keras is out of date. Please use 2.12 or higher.
			time : string
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0181002  
				  Bad request.  
				- E.SC.API.0181007  
				  Specified converter_version does not support the model's keras version.  
				- E.SC.API.0181008  
				  The model file exceed size limit.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0181003  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0181001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0181004  
				  Internal server error.  
				- E.SC.API.0181005  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}', headers=headers, method='POST', model_id=model_id, device_id=device_id, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteModel(self, model_id:str, grant_type:str=None):
        """
		Deletes the base model, device model, and projects associated with the specified model ID.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS or WARNING.
			code : string
				Error code.
			message : string
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- W.SC.API.0078002  
				  The model deletion process is complete. However  
			time : string
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0078003  
				  Since preparations for deletion have not been completed  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0078004  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- W.SC.API.0078001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}', headers=headers, method='DELETE', model_id=model_id, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateModel(self, model_id:str, comment:str=None, version_number:str=None, grant_type:str=None):
        """
		Updates attribute information of the specified model.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model. The maximum number of characters that can be specified is 100.
		comment : str
			Description of the subject. The maximum number of characters that can be specified is 100.
		version_number : str
			Name of the vendor. The maximum number of characters that can be specified is 100.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0073001  
				  Invalid parameter comment.  
				- E.SC.API.0073002  
				  Invalid parameter vendor_name.  
				- E.SC.API.0073003  
				  Parameter is not set.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0073004  
				  Not found.  
				- E.SC.API.0073006  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0073005  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}', headers=headers, method='PATCH', model_id=model_id, comment=comment, version_number=version_number, grant_type=grant_type)
        return ret

    @debug_print
    def GetBaseModelStatus(self, model_id:str, latest_type:str=None, grant_type:str=None):
        """
		Returns an information of the specified base model.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		latest_type : str
			Classification of the latest version. 
			- Value definition:  
			  0: Latest version after publication.  
			  1: Latest version after completion of the conversion process or publication.
			Default value : 1
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			model_id : string
				The model ID.
			model_type : string
				The model type.
			functionality : string
				The function descriptions.
			vendor_name : string
				The vendor's name.
			model_comment : string
				The description of the subject.
			network_type : string
				The network type.
			create_by : string
				Returns the create_by.
				- Value definition:  
				  Self: Self-training models
				  Marketplace: Marketplace purchasing model
			package_id : string
				The marketplace package ID.
			product_id : string
				The marketplace product ID.
			metadata_format_id : string
				The metadata_format_id.
			projects : array
				model_project_name : string
					The model project name.
				model_project_id : string
					The model project ID.
				model_platform : string
					The model platform.
				model_type : string
					The model type.
				project_type : string
					The project type.
				device_id : string
					The device ID.
				versions : array
					There must be one subordinate element for this API.
					version_number : string
						The version number.
					iteration_id : string
						The iteration ID.
					iteration_name : string
						The iteration name.
					accuracy : string
						The accuracy.
					model_performances : object
						The performance information of the AI model.
					latest_flg : string
						The latest flag.
					publish_latest_flg : string
						The latest published flag.
					version_status : string
						The status.
					org_file_name : string
						The pre-conversion model filename.
					org_file_size : integer
						The publish model file size.
					publish_file_name : string
						The publish model filename.
					publish_file_size : integer
						The publish model file size.
					model_file_size : integer
						The model file size.
					model_framework : string
						The model framework.
					conv_id : string
						The conversion request ID.
					labels : array
						The label array.
					stage : string
						The conversion stage.
					result : string
						The conversion result.
					kpi : object
					converter_log : array
						converter log.
					convert_start_date : string
						The conversion start date.
					convert_end_date : string
						The conversion end date.
					publish_start_date : string
						The publish start date.
					publish_end_date : string
						The publish end date.
					version_comment : string
						The description of the subject.
					version_ins_date : string
						The created time of the version.
					version_upd_date : string
						The created time of the version.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0057001  
				  Invalid parameter latest_type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0057002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}/base', headers=headers, method='GET', model_id=model_id, latest_type=latest_type, grant_type=grant_type)
        return ret

    @debug_print
    def GetBaseModelVersions(self, model_id:str, version_number:str=None, grant_type:str=None):
        """
		Returns a list of base model version.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		version_number : str
			Version number.
		scope
			The scope of response parameters to return.
			- Value definition:  
			 full: Returns all parameters  
			 minimal: Returns minimal parameters *effective for timesaving
			Default value : full
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			model_id : string
				The model ID.
			model_type : string
				The model type.
			functionality : string
				The function descriptions.
			vendor_name : string
				The vendor's name.
			model_comment : string
				The description of the subject.
			network_type : string
				The network type.
			create_by : string
				Returns the create_by.
				- Value definition:  
				  Self: Self-training models
				  Marketplace: Marketplace purchasing model
			package_id : string
				The marketplace package ID.
			product_id : string
				The marketplace product ID.
			metadata_format_id : string
				The metadata_format_id.
			projects : array
				model_project_name : string
					The model project name.
				model_project_id : string
					The model project ID.
				model_platform : string
					The model platform.
				model_type : string
					The model type.
				project_type : string
					The project type.
				device_id : string
					The device ID.
				versions : array
					There must be one subordinate element for this API.
					version_number : string
						The version number.
					iteration_id : string
						The iteration ID.
					iteration_name : string
						The iteration name.
					accuracy : string
						The accuracy.
					model_performances : object
						The performance information of the AI model.
					latest_flg : string
						The latest flag.
					publish_latest_flg : string
						The latest published flag.
					version_status : string
						The status.
					org_file_name : string
						The pre-conversion model filename.
					org_file_size : integer
						The publish model file size.
					publish_file_name : string
						The publish model filename.
					publish_file_size : integer
						The publish model file size.
					model_file_size : integer
						The model file size.
					model_framework : string
						The model framework.
					conv_id : string
						The conversion request ID.
					labels : array
						The label array.
					stage : string
						The conversion stage.
					result : string
						The conversion result.
					kpi : object
					converter_log : array
						converter log.
					convert_start_date : string
						The conversion start date.
					convert_end_date : string
						The conversion end date.
					publish_start_date : string
						The publish start date.
					publish_end_date : string
						The publish end date.
					version_comment : string
						The description of the subject.
					version_ins_date : string
						The created time of the version.
					version_upd_date : string
						The created time of the version.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0058001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}/base/versions', headers=headers, method='GET', model_id=model_id, version_number=version_number, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateBaseModelVersion(self, model_id:str, version_number:str, payload=None, grant_type:str=None):
        """
		Updates attribute information of the specified base model version.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		version_number : str (required) 
			Version number.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		comment : string
			Description of version. The maximum number of characters that can be specified is 100. 
		input_format_param : string
			SAS URL or Presigned URL of the input format param file.  
			*Usage: Packager conversion information (image format information).  
			*The json format is an array of objects. Each object contains the following values.  
			 ・ordinal: Order of DNN input to converter (value range: 0 to 2)  
			 ・format: Format ("RGB" or "BGR")  
			*Example:  
			 [{  
			     "ordinal": 0,  
			     "format": "RGB"  
			 },  
			 {  
			     "ordinal": 1,  
			     "format": "RGB"  
			 }]  
		network_config : string
			SAS URL or Presigned URL of the network config file.  
			*Usage: Conversion parameter information of the model converter. Therefore, it is not necessary to specify when specifying the AI model before conversion.  
			*Example:  
			 {  
			   "Postprocessor": {  
			     "params": {  
			       "background": false,  
			       "scale_factors": [  
			         10.0,  
			         10.0,  
			         5.0,  
			         5.0  
			       ],  
			       "score_thresh": 0.01,  
			       "max_size_per_class": 64,  
			       "max_total_size": 64,  
			       "clip_window": [  
			         0,  
			         0,  
			         1,  
			         1  
			       ],  
			       "iou_threshold": 0.45  
			     }  
			   }  
			 }  

		Returns:
		------------------------------
		[200] Successful Response:
			model_id : string
				The model ID.
			model_type : string
				The model type.
			functionality : string
				The function descriptions.
			vendor_name : string
				The vendor's name.
			model_comment : string
				The description of the subject.
			network_type : string
				The network type.
			create_by : string
				Returns the create_by.
				- Value definition:  
				  Self: Self-training models
				  Marketplace: Marketplace purchasing model
			package_id : string
				The marketplace package ID.
			product_id : string
				The marketplace product ID.
			metadata_format_id : string
				The metadata_format_id.
			projects : array
				model_project_name : string
					The model project name.
				model_project_id : string
					The model project ID.
				model_platform : string
					The model platform.
				model_type : string
					The model type.
				project_type : string
					The project type.
				device_id : string
					The device ID.
				versions : array
					There must be one subordinate element for this API.
					version_number : string
						The version number.
					iteration_id : string
						The iteration ID.
					iteration_name : string
						The iteration name.
					accuracy : string
						The accuracy.
					model_performances : object
						The performance information of the AI model.
					latest_flg : string
						The latest flag.
					publish_latest_flg : string
						The latest published flag.
					version_status : string
						The status.
					org_file_name : string
						The pre-conversion model filename.
					org_file_size : integer
						The publish model file size.
					publish_file_name : string
						The publish model filename.
					publish_file_size : integer
						The publish model file size.
					model_file_size : integer
						The model file size.
					model_framework : string
						The model framework.
					conv_id : string
						The conversion request ID.
					labels : array
						The label array.
					stage : string
						The conversion stage.
					result : string
						The conversion result.
					kpi : object
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0076001  
				  Json format is invalid.  
				- E.SC.API.0076002  
				  Parameter is not set.  
				- E.SC.API.0076003  
				  Invalid parameter comment.  
				- E.SC.API.0076004  
				  Parameter input_format_param or network_config is not set.  
				- E.SC.API.0076006  
				  Bad request.  
				- E.SC.API.0076012  
				  Bad request.  
				- E.SC.API.0076013  
				  Invalid parameter input_format_param.  
				- E.SC.API.0076014  
				  Invalid parameter network_config.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0076005  
				  Not found.  
				- E.SC.API.0076010  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0076007  
				  Internal server error.  
				- E.SC.API.0076008  
				  Internal server error.  
				- E.SC.API.0076009  
				  Internal server error.  
				- E.SC.API.0076011  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/models/{model_id}/base/versions/{version_number}', headers=headers, method='PATCH', model_id=model_id, version_number=version_number, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceModelStatus(self, model_id:str, device_id:str, latest_type:str=None, grant_type:str=None):
        """
		Returns an information of the specified device model.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		device_id : str (required) 
			Device ID.
		latest_type : str
			Classification of the latest version. 
			- Value definition:  
			  0: Latest version after publication.  
			  1: Latest version after completion of the conversion process or publication.
			Default value : 1
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			model_id : string
				The model ID.
			model_type : string
				The model type.
			functionality : string
				The function descriptions.
			vendor_name : string
				The vendor's name.
			model_comment : string
				The description of the subject.
			network_type : string
				The network type.
			create_by : string
				Returns the create_by.
				- Value definition:  
				  Self: Self-training models
				  Marketplace: Marketplace purchasing model
			package_id : string
				The marketplace package ID.
			product_id : string
				The marketplace product ID.
			metadata_format_id : string
				The metadata_format_id.
			projects : array
				model_project_name : string
					The model project name.
				model_project_id : string
					The model project ID.
				model_platform : string
					The model platform.
				model_type : string
					The model type.
				project_type : string
					The project type.
				device_id : string
					The device ID.
				versions : array
					There must be one subordinate element for this API.
					version_number : string
						The version number.
					iteration_id : string
						The iteration ID.
					iteration_name : string
						The iteration name.
					accuracy : string
						The accuracy.
					model_performances : object
						The performance information of the AI model.
					latest_flg : string
						The latest flag.
					publish_latest_flg : string
						The latest published flag.
					version_status : string
						The status.
					org_file_name : string
						The pre-conversion model filename.
					org_file_size : integer
						The publish model file size.
					publish_file_name : string
						The publish model filename.
					publish_file_size : integer
						The publish model file size.
					model_file_size : integer
						The model file size.
					model_framework : string
						The model framework.
					conv_id : string
						The conversion request ID.
					labels : array
						The label array.
					stage : string
						The conversion stage.
					result : string
						The conversion result.
					kpi : object
					converter_log : array
						converter log.
					convert_start_date : string
						The conversion start date.
					convert_end_date : string
						The conversion end date.
					publish_start_date : string
						The publish start date.
					publish_end_date : string
						The publish end date.
					version_comment : string
						The description of the subject.
					version_ins_date : string
						The created time of the version.
					version_upd_date : string
						The created time of the version.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0060001  
				  Invalid parameter latest_type.  
				- E.SC.API.0060002  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}/devices/{device_id}', headers=headers, method='GET', model_id=model_id, device_id=device_id, latest_type=latest_type, grant_type=grant_type)
        return ret

    @debug_print
    def GetDeviceModelVersions(self, model_id:str, device_id:str, version_number:str=None, grant_type:str=None):
        """
		Returns a list of device model version information.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		device_id : str (required) 
			Device ID.
		scope
			The scope of response parameters to return.
			- Value definition:  
			 full: Returns all parameters  
			 minimal: Returns minimal parameters *effective for timesaving
			Default value : full
		version_number : str
			Version number.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			model_id : string
				The model ID.
			model_type : string
				The model type.
			functionality : string
				The function descriptions.
			vendor_name : string
				The vendor's name.
			model_comment : string
				The description of the subject.
			network_type : string
				The network type.
			create_by : string
				Returns the create_by.
				- Value definition:  
				  Self: Self-training models
				  Marketplace: Marketplace purchasing model
			package_id : string
				The marketplace package ID.
			product_id : string
				The marketplace product ID.
			metadata_format_id : string
				The metadata_format_id.
			projects : array
				model_project_name : string
					The model project name.
				model_project_id : string
					The model project ID.
				model_platform : string
					The model platform.
				model_type : string
					The model type.
				project_type : string
					The project type.
				device_id : string
					The device ID.
				versions : array
					There must be one subordinate element for this API.
					version_number : string
						The version number.
					iteration_id : string
						The iteration ID.
					iteration_name : string
						The iteration name.
					accuracy : string
						The accuracy.
					model_performances : object
						The performance information of the AI model.
					latest_flg : string
						The latest flag.
					publish_latest_flg : string
						The latest published flag.
					version_status : string
						The status.
					org_file_name : string
						The pre-conversion model filename.
					org_file_size : integer
						The publish model file size.
					publish_file_name : string
						The publish model filename.
					publish_file_size : integer
						The publish model file size.
					model_file_size : integer
						The model file size.
					model_framework : string
						The model framework.
					conv_id : string
						The conversion request ID.
					labels : array
						The label array.
					stage : string
						The conversion stage.
					result : string
						The conversion result.
					kpi : object
					converter_log : array
						converter log.
					convert_start_date : string
						The conversion start date.
					convert_end_date : string
						The conversion end date.
					publish_start_date : string
						The publish start date.
					publish_end_date : string
						The publish end date.
					version_comment : string
						The description of the subject.
					version_ins_date : string
						The created time of the version.
					version_upd_date : string
						The created time of the version.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0061001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}/devices/{device_id}/versions', headers=headers, method='GET', model_id=model_id, device_id=device_id, version_number=version_number, grant_type=grant_type)
        return ret

    @debug_print
    def UpdateDeviceModelVersion(self, model_id:str, device_id:str, version_number:str, payload, grant_type:str=None):
        """
		Updates attribute information of the AI model version for the specified Edge Device.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		device_id : str (required) 
			Device ID.
		version_number : str (required) 
			Version number.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		comment : string (required)
			Description of version.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0077001  
				  Invalid parameter comment.  
				- E.SC.API.0077002  
				  Parameter is not set.  
				- E.SC.API.0077006  
				  Json format is invalid.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0077003  
				  Not found.  
				- E.SC.API.0077005  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0077004  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/models/{model_id}/devices/{device_id}/versions/{version_number}', headers=headers, method='PATCH', model_id=model_id, device_id=device_id, version_number=version_number, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetDnnParams(self, model_id:str, version_number:str=None, device_id:str=None, grant_type:str=None):
        """
		Returns dnn_params of the specified model.

		Parameters:
		------------------------------
		model_id : str (required) 
			ID of the AI model.
		version_number : str
			Version number.
			Default value : latest
		device_id : str
			Device ID  
			*Only available for device models. 
			This parameter is only available for deploying base models.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] SUCCESS:
			contents : string (required)
				Returns base64-encoded dnnParams.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0272002  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0272003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0272001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/models/{model_id}/dnn_params', headers=headers, method='GET', model_id=model_id, version_number=version_number, device_id=device_id, grant_type=grant_type)
        return ret

    @debug_print
    def GetModelBundles(self, model_bundle_name:str=None):
        """
		Get model bundle list.

		Parameters:
		------------------------------
		model_bundle_name : str
			Model Bundle Name.

		Returns:
		------------------------------
		[200] Successful Response:
			model_bundles : array (required)
				model_bundle_name : string
					Set the model bundle name.
				description : string
					Set the model bundle description.
				create_date : string
					Set the create time of model bundle.
				latest_version : object
					ai_model_bundle_id : string
						Set the AI model bundle ID.
					model_bundle_version : string
						Set the model bundle version number.
					encrypt_status : string
						Set the encrypt status.
						- Value definition:  
						  01: Before Encrypt  
						  02: Encrypting  
						  03: Encrypt Compeleted  
						  04: Encrypt Failed  
						  05: Encrypt Error  
					create_date : string
						Set the create time of the version.
					update_date : string
						Set the update time of the version.
		[401] Authorization Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_bundles', headers=headers, method='GET', model_bundle_name=model_bundle_name)
        return ret

    @debug_print
    def ImportModelBundle(self, payload):
        """
		Imports a model bundle into your project.

		Payload:
		------------------------------
		bundle_name : string (required)
			Model bundle name for new registration or version upgrade. The maximum number of characters that can be specified is 100.
		vendor_name : string
			Name of the vendor. The maximum number of characters that can be specified is 100.  
		description : string
			Description of the subject. The maximum number of characters that can be specified is 100.  
			*When saving a new model bundle, a same value is set to model bundle and model_bundle_version parameters.
			*When updating a model bundle, any string can be set for model_bundle_version.
		bundle_file_id : string
			File ID of the model bundle file.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0297001  
				  Invalid parameter bundle_name.  
				- E.SC.API.0297002  
				  Invalid parameter vender_name.  
				- E.SC.API.0297003  
				  The file header is invalid.  
				- E.SC.API.0297009  
				  Invalid parameter description.  
				- E.SC.API.0297010  
				  Invalid parameter bundle_file_id.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0297004  
				  Internal server error.  
				- E.SC.API.0297005  
				  Internal server error.  
				- E.SC.API.0297006  
				  Internal server error.  
				- E.SC.API.0297007  
				  Internal server error.  
				- E.SC.API.0297008  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/model_bundles', headers=headers, method='POST', payload=payload)
        return ret

    @debug_print
    def DeleteModelBundle(self, model_bundle_name:str):
        """
		Delete the model bundle associated with the specified model bundle name.

		Parameters:
		------------------------------
		model_bundle_name : str (required) 
			Model bundle name.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				Set "SUCCESS" or "WARNING".
			code : string
				Error code.
			message : string
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- W.SC.API.0298002  
				  The model bundle deletion process is complete. However, some processes have been skipped due to reasons such as having already been deleted. 
			time : string
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000006  
				  Bad request.  
				- W.SC.API.0298003  
				  Since preparations for deletion have not been completed, wait for a while before deleting.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- W.SC.API.0298001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000014  
				  Too Many Requests.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_bundles/{model_bundle_name}', headers=headers, method='DELETE', model_bundle_name=model_bundle_name)
        return ret

    @debug_print
    def GetModelBundleVersions(self, model_bundle_name:str, version_number:str=None):
        """
		Get model bundle version list.

		Parameters:
		------------------------------
		model_bundle_name : str (required) 
			Model Bundle Name.
		version_number : str
			Version number.

		Returns:
		------------------------------
		[200] Successful Response:
			model_bundle_name : string
				Set the model bundle name.
			description : string
				Set the model bundle description.
			create_date : string
				Set the create time of model bundle.
			versions : array
				ai_model_bundle_id : string
					Set the AI model bundle ID.
				model_bundle_version : string
					Set the model bundle version ID.
				latest_flg : string
					Set the latest flag.
				encrypt_status : string
					Set the encrypt status.
					- Value definition:  
					  01: Before Encrypt  
					  02: Encrypting  
					  03: Encrypt Compeleted  
					  04: Encrypt Failed  
					  05: Encrypt Error  
				create_date : string
					Set the create time of the version.
				update_date : string
					Set the update time of the version.
		[400] Bad Request:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0296001  
				  Bad request.   
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/model_bundles/{model_bundle_name}/versions', headers=headers, method='GET', model_bundle_name=model_bundle_name, version_number=version_number)
        return ret

    @debug_print
    def GetFirmwares(self, limit:int=None, starting_after:str=None, firmware_type:str=None, target_device_type:str=None, grant_type:str=None):
        """
		Lists the information of the chosen Edge System Software.

		Parameters:
		------------------------------
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 20
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		firmware_type : str
			Type of the Edge System Software.
		target_device_type : str
			Type of the target device.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			firmwares : array (required)
				firmware_id : string
					The firmware ID returned in the response from the GetFirmwares API.
				firmware_type : string
					Type of the Edge System Software.
					Enum:
						'edge_system_sw_package'
				firmware_version : string
					Version of the Edge System Software.
				description : string
					Description of the Edge System Software.
				ins_id : string
					The subject that registered the Edge System Software.
				ins_date : string
					The date the Edge System Software was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				upd_id : string
					The subject that updated the Edge System Software.
				upd_date : string
					The date the Edge System Software was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
				target_device_types : array
					Type of the target device.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0023001
				  Invalid parameter firmware_type.
				- E.SC.API.0023003
				  Invalid parameter limit.
				- E.SC.API.0023004
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/firmwares', headers=headers, method='GET', limit=limit, starting_after=starting_after, firmware_type=firmware_type, target_device_type=target_device_type, grant_type=grant_type)
        return ret

    @debug_print
    def CreateFirmware(self, payload, grant_type:str=None):
        """
		Registers the Edge System Software to the Console.

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		firmware_type : string (required)
			Type of the Edge System Software.
			Enum:
				'edge_system_sw_package'
		description : string
			description. The maximum number of characters that can be specified is 100.
		file_id : string (required)
			The file ID returned in the response from the UploadFile API.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0025017  
				  Invalid parameter file_id.  
				- E.SC.API.0025020  
				  Invalid firmware package file.  
				- E.SC.API.0025021  
				  The specified firmware has registered.  
				- E.SC.API.0025022  
				  Invalid parameter firmware_type.  
				- E.SC.API.0025023  
				  Bad request.  
				- E.SC.API.0025024  
				  Invalid parameter description.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0025005  
				  Not found.  
				- E.SC.API.0025019  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.   
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/firmwares', headers=headers, method='POST', payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetFirmware(self, firmware_id:str, grant_type:str=None):
        """
		Returns the information of a specific Edge System Software.

		Parameters:
		------------------------------
		firmware_id : str (required) 
			Firmware ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			firmware_id : string
				The firmware ID returned in the response from the GetFirmwares API.
			firmware_type : string
				Returns the Edge System Software type.
				Enum:
					'edge_system_sw_package'
			firmware_version : string
				Returns the Edge System Software version.
			description : string
				The Edge System Software description.
			ins_id : string
				The subject that registered the Edge System Software.
			ins_date : string
				The date the Edge System Software was created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			upd_id : string
				The subject that updated the Edge System Software.
			upd_date : string
				The date the Edge System Software was updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			target_device_types : array
				Type of the target device.
			manifest : object
				The package manifest.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0024003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/firmwares/{firmware_id}', headers=headers, method='GET', firmware_id=firmware_id, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteFirmware(self, firmware_id:str, grant_type:str=None):
        """
		Deletes the specified Edge System Software from the Console.

		Parameters:
		------------------------------
		firmware_id : str (required) 
			Firmware ID
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS or WARNING.
			code : string
				Error code.
			message : string
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- W.SC.API.0026004  
				  Not found.  
			time : string
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0026001  
				  Common firmware cannot be deleted.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- W.SC.API.0026003  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0026002  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/firmwares/{firmware_id}', headers=headers, method='DELETE', firmware_id=firmware_id, grant_type=grant_type)
        return ret

    @debug_print
    def GetEdgeApps(self, limit:int=None, starting_after:str=None, grant_type:str=None):
        """
		Returns a list of registered Edge Applications.

		Parameters:
		------------------------------
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 20
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			apps : array (required)
				app_name : string
					The application name.
				versions : array
					app_version : string
						Returns the application version number.
					root_dtmi : string
						Returns the root DTMI.
					compiled_flg : boolean
						The compiled flg.
						- Value definition:  
						  false: Specified App is not compiled  
						  true: Specified App is compiled
					status : string
						The compile status.
						Enum:
							'before_compile'
							'compiling'
							'compiled'
							'failed'
					description : string
						Description of the subject.
					deploy_count : integer
						In this application version, the parameter is fixed to zero.
					ins_id : string
						The subject that configured the feature.
					ins_date : string
						The date the settings were created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
					upd_id : string
						The subject that updated the settings.
					upd_date : string
						The date the settings were updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006
				  Bad request.
				- E.SC.API.0171001
				  Invalid parameter limit.
				- E.SC.API.0171002
				  Invalid parameter starting after.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/edge_apps', headers=headers, method='GET', limit=limit, starting_after=starting_after, grant_type=grant_type)
        return ret

    @debug_print
    def ImportEdgeApp(self, payload, grant_type:str=None):
        """
		Imports Edge Application to the Console.

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		description : string
			Description of the subject. The maximum number of characters that can be specified is 100.
		app_name : string
			Specify if you want to use a different The application name. from the one in the package.
		edge_app_package_id : string (required)
			The Edge App Package file ID returned in the response from the UploadFile API.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0170011  
				  The specified app has already been registered.  
				- E.SC.API.0170018  
				  Invalid json format  
				- E.SC.API.0170019  
				  Invalid json format  
				- E.SC.API.0170020  
				  Invalid json format.  
				- E.SC.API.0170021  
				  Invalid json format  
				- E.SC.API.0170022  
				  Invalid parameter root_dtdl_file_id.  
				- E.SC.API.0170023  
				  Invalid parameter dtdl_file_ids.  
				- E.SC.API.0170025  
				  Parameter edge_app_file_id is not set.  
				- E.SC.API.0170026  
				  Invalid parameter edge_app_file_id.  
				- E.SC.API.0170027  
				  Parameter root_dtdl_file_id is not set.  
				- E.SC.API.0170028  
				  Invalid edge app package file.  
				- E.SC.API.0170030  
				  Bad request.  
				- E.SC.API.0170032  
				  Parameter edge_app_package_id is not set.  
				- E.SC.API.0170033  
				  The length of parameter app_name and version exceeds limit.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0170017  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0170029  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[409] Conflict:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0170024  
				  Another DTDL with the same DTMI as the DTDL you are trying to register has already been registered.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0170013  
				  Make sign failed.  
				- E.SC.API.0170014  
				  File upload failed.  
				- E.SC.API.0170015  
				  Failed to create app.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/edge_apps', headers=headers, method='POST', payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetEdgeApp(self, app_name:str, app_version:str, grant_type:str=None):
        """
		Returns the information of a specific Edge Application.

		Parameters:
		------------------------------
		app_name : str (required) 
			The application name.
		app_version : str (required) 
			The application version.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			app_name : string
				The application name.
			app_version : string
				Returns the application version.
			root_dtmi : string
				Returns the root DTMI.
			compiled_flg : boolean
				Set the compiled flag.
				- Value definition  
				  false : Specified App is not compiled  
				  true : Specified App is compiled
			status : string
				The compile status.
				Enum:
					'before_compile'
					'compiling'
					'compiled'
					'failed'
			description : string
				Description of the subject.
			deploy_count : integer
				In this application version, the parameter is fixed to zero.
			ins_id : string
				The subject that configured the feature.
			ins_date : string
				The date the settings were created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
			upd_id : string
				The subject that updated the settings.
			upd_date : string
				The date the settings were updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0172001  
				  The specified parameter app_name or version_number is not registered.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/edge_apps/{app_name}/{app_version}', headers=headers, method='GET', app_name=app_name, app_version=app_version, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteEdgeApp(self, app_name:str, app_version:str, grant_type:str=None):
        """
		Deletes the specified Edge Application from the Console.

		Parameters:
		------------------------------
		app_name : str (required) 
			The application name.
		app_version : str (required) 
			The application version.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
				- E.SC.API.0173003  
				  Unauthorized operation.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- W.SC.API.0173001  
				  The specified parameter app_name or version_number is not registered.  
				- W.SC.API.0173002  
				  App file does not exist.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/edge_apps/{app_name}/{app_version}', headers=headers, method='DELETE', app_name=app_name, app_version=app_version, grant_type=grant_type)
        return ret

    @debug_print
    def ExportEdgeApp(self, app_name:str, app_version:str, grant_type:str=None):
        """
		Exports the specified Edge Application information.

		Parameters:
		------------------------------
		app_name : str (required) 
			The application name.
		app_version : str (required) 
			The application version.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			contents : string (required)
				Contents of the file in base64-encoded format.
			file_name : string (required)
				Name of the subject file.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0177001  
				  The specified parameter app_name or version_number is not registered.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/edge_apps/{app_name}/{app_version}/export', headers=headers, method='GET', app_name=app_name, app_version=app_version, grant_type=grant_type)
        return ret

    @debug_print
    def GetEdgeAppDeploys(self, app_name:str, app_version:str, limit:int=None, starting_after:str=None, grant_type:str=None):
        """
		Returns the specified Edge Application deployment status.

		Parameters:
		------------------------------
		app_name : str (required) 
			The application name.
		app_version : str (required) 
			The application version.
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 20
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			deploys : array (required)
				id : string
					The deploy ID.
				total_status : string
					The total status.
					- Value definition:
					  0: Running
					  1: Successfully completed
					  2: Failed
					  3: Canceled
					  9: Undeploy
				deploy_parameter : string
					The deploy parameter.
				devices : array
					device_id : string
						The device ID.
					status : string
						The total status.
						- Value definition:
						  0: Running
						  1: Successfully completed
						  2: Failed
						  3: Canceled
					latest_deployment_flg : string
						The deployment flg.
						- Value definition:
						  0: Old deployment history
						  1: Recent deployment history
					ins_id : string
						The subject that configured the feature.
					ins_date : string
						The date the settings were created.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
					upd_id : string
						The subject that updated the settings.
					upd_date : string
						The date the settings were updated.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0178001  
				  The specified parameter app_name or version_number is not registered.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/edge_apps/{app_name}/{app_version}/deploys', headers=headers, method='GET', app_name=app_name, app_version=app_version, limit=limit, starting_after=starting_after, grant_type=grant_type)
        return ret

    @debug_print
    def GetImageDirectories(self, device_id:str=None, include_deleted_device:bool=None, grant_type:str=None):
        """
		Returns the directory information (device group and device information) where images are stored.

		Parameters:
		------------------------------
		device_id : str
			Device ID. 
			If this is specified, return an image directory list linked to the specified device ID. 
		include_deleted_device : bool
			Specify whether to delete images from devices that have been removed from the Console.
			Default value : False
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0106001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/images/devices/directories', headers=headers, method='GET', device_id=device_id, include_deleted_device=include_deleted_device, grant_type=grant_type)
        return ret

    @debug_print
    def GetImages(self, device_id:str, sub_directory_name:str, limit:int=None, starting_after:str=None, name_starts_with:str=None, grant_type:str=None):
        """
		Returns a SAS URL to download images from a specific device. Copy the URL to access the data. 
		The URL will expire after one hour. 
		*Application: Use to display an image in a UI

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		sub_directory_name : str (required) 
			Directory name. 
		limit : int
			Number of the items to fetch information.  
			Value range: 1 to 256
			Default value : 50
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). Specify the value obtained from the response (continuation_token) to fetch the next data.
		name_starts_with : str
			Return only objects that forward match the input string
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			continuation_token : string (required)
				Last token of extracted data. If there is no continuation data, it will be empty.
			data : array (required)
				name : string (required)
					The image filename.
				sas_url : string (required)
					SAS url of image.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0107010  
				  Invalid starting after or error fetching blobs.  
				- E.SC.API.0107011  
				  Invalid parameter limit.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0107001  
				  Not found.  
				- E.SC.API.0107006  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/images/devices/{device_id}/directories/{sub_directory_name}', headers=headers, method='GET', device_id=device_id, sub_directory_name=sub_directory_name, limit=limit, starting_after=starting_after, name_starts_with=name_starts_with, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteImages(self, device_id:str, sub_directory_name:str, payload, grant_type:str=None):
        """
		Deletes the saved images from a specific Edge Device.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID.
		sub_directory_name : str (required) 
			Directory name. 
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		directory_deletion : string
			The directory deletion flag.
			- Value definition:  
			  0: Delete by specifying a file
			  1: Delete files by specifying a directory
		filenames : array
			Specify the file name to delete when the value of directory_deletion is set to 0.
		limit : integer
			Number of the items to be deleted. The oldest stored items are deleted first.
			Value range: 1 to 10000

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0198002  
				  Invalid parameter sub_directory_name.  
				- E.SC.API.0198003  
				  Invalid parameter filenames.  
				- E.SC.API.0198006  
				  Invalid parameter directory_deletion.  
				- E.SC.API.0198007  
				  Unable to send message to queue.  
				- E.SC.API.0198008  
				  Invalid parameter limit.  
				- W.SC.API.0198005  
				  {0} does not exist.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0198001  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0198004  
				  Delete {0} failed.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/images/devices/{device_id}/directories/{sub_directory_name}', headers=headers, method='DELETE', device_id=device_id, sub_directory_name=sub_directory_name, payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def DeleteInferenceResults(self, device_id:str, item_ids:str, include_deleted_device:bool=None, grant_type:str=None):
        """
		Deletes the inference data retrieved through the GetInferenceResults.

		Parameters:
		------------------------------
		device_id : str (required) 
			Device ID
		item_ids : str (required) 
			The ID of the inference result to be deleted, obtained from GetInferenceResults.
		include_deleted_device : bool
			Specify whether to also delete inference results from devices that have been removed from the Console.
			Default value : False
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0290002  
				  Invalid parameter items_ids.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0290001
				  Not found.
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0290003  
				  Delete {0} failed.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/inferenceresults/devices/{device_id}', headers=headers, method='DELETE', device_id=device_id, item_ids=item_ids, include_deleted_device=include_deleted_device, grant_type=grant_type)
        return ret

    @debug_print
    def Retrievealistofinferences(self, devices, limit:int=None, starting_after:str=None, from_datetime:str=None, to_datetime:str=None):
        """
		Returns a list of inferences with optional filters for devices and time range.

		Parameters:
		------------------------------
		devices : array (required) 
			A device ID or a list of device IDs to obtain inferences from,
			with a minimum number of 1 and a maximum of 10.
		limit : int
			The number of inferences to retrieve. The default is 50, with a minimum of 1 and a maximum of 500.
			Default value : 50
		starting_after : str
			Retrieves additional data beyond the number of targets specified by the query parameter (limit). 
			Specify the value obtained from the response (continuation_token) to fetch the next data.
		from_datetime : str
			The start datetime for filtering inferences (in ISO-8601 format).
			- Format: yyyyMMddThhmmss.SSSSSS or yyyy-MM-ddThh:mm:ss.SSSSSS (ISO-8601)
		to_datetime : str
			The end datetime for filtering inferences (in ISO-8601 format).
			- Format: yyyyMMddThhmmss.SSSSSS or yyyy-MM-ddThh:mm:ss.SSSSSS (ISO-8601)

		Returns:
		------------------------------
		[200] A list of inferences:
			continuation_token : string
				Last token of extracted data. If there is no continuation data, it will be empty.
			inferences : array
				id : string
					The inference ID.
				model_id : string
					The model ID.
				model_version_id : string
					The model version ID.
				device_id : string
					The ID of the device that generated the inference result.
				project_id : string
					The ID of the project associated with the inference result.
				inferences : array
					T : string
						Time when retrieving data from the sensor.
					O : string
						Output tensor (Encoding format).
				image : boolean
					Whether the returned inference results are associated with any image data.
		[400] Bad Request:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000006  
				  Bad request.
				- E.SC.API.0108007
				  Invalid parameter from_datetime
				- E.SC.API.0108008
				  Invalid parameter to_datetime
				- E.SC.API.0108010  
				  Invalid parameter limit.
				- E.SC.API.0108011
				  Invalid number of devices
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[401] Authorization Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[403] Forbidden:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000014  
				  Too Many Requests.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[500] Internal Server Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[503] Service Unavailable:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/inferenceresults', headers=headers, method='GET', devices=devices, limit=limit, starting_after=starting_after, from_datetime=from_datetime, to_datetime=to_datetime)
        return ret

    @debug_print
    def GetIRHubConnector(self):
        """
		Get the inference result hub connector.

		Returns:
		------------------------------
		[200] Successful Response:
			<One of type : IrHubConnectorDefault>
				type : string (required)
					The platform where the system should send the inference results.
				url : string (required)
					Set empty string.
				name : string (required)
					Set empty string.
			<One of type : IrHubConnectorAzureBlobStorage>
				type : string (required)
					The platform where the system should send the inference results.
				url : string (required)
					Connection string for Azure Blob Storage.
				name : string (required)
					The name of the blob container within Azure storage account.
			<One of type : IrHubConnectorAzureEventHub>
				type : string (required)
					The platform where the system should send the inference results.
				url : string (required)
					Connection string for Azure Event Hubs.
				name : string (required)
					The name of the Azure EventHub entity.
			<One of type : IrHubConnectorAwsKinesis>
				type : string (required)
					The platform where the system should send the inference results.
				name : string (required)
					The name of the AWS Kinesis where the data will be stored.
				secret_access_key : string
					Partly masked value of AWS secret access key for writing into the destination kinesis.
				access_key : string
					Partly masked value of AWS access key for writing into the destination kinesis.
			<One of type : IrHubConnectorAwsS3>
				type : string (required)
					The platform where the system should send the inference results.
				name : string (required)
					The name of the AWS S3 bucket where the data will be stored.
				secret_access_key : string (required)
					Partly masked value of AWS secret access key for writing into the destination bucket.
				access_key : string (required)
					Partly masked value of AWS access key for writing into the destination bucket.
			<One of type : IrHubConnectorKafka>
				type : string (required)
					The platform where the system should send the inference results.
				name : string (required)
					The name of the configured Kafka topic
				username : string
					The Username to authenticate. This value is masked (replaced with asterisks) to ensure sensitive data remains secure and unreadable.
				password : string
					Password to authenticate. This value is masked (replaced with asterisks) to ensure sensitive data remains secure and unreadable.
				client_id : string
					Value used to categorize or identify the source of messages. This value is masked (replaced with asterisks) to ensure sensitive data remains secure and unreadable.
				bootstrap_servers : string (required)
					The list of Kafka endpoints the service could reach. At least two are recommended. This value is masked in responses and logs (e.g., replaced with asterisks) when authentication via username and password is not required.
		[400] Bad Request:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000006  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[401] Authorization Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[403] Forbidden:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[422] Unprocessable entity:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000014  
				  Too Many Requests.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[500] Internal Server Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[503] Service Unavailable:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/connector/ir_hub', headers=headers, method='GET')
        return ret

    @debug_print
    def UpdateIRHubConnector(self, payload=None, grant_type:str=None):
        """
		Updates the external transfer settings to forward inference results obtained from Edge Devices to Azure Event Hubs.

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		<One of type : AzureEventHub>
			type : string (required)
				The platform type where the system should store the inference results. Set "AzureEventHub". *Connector would be initial setting if type is "".
			url : string (required)
				Connection string for Azure Event Hubs.
			name : string (required)
				The name of Azure Event Hubs Instance Name.
		<One of type : AzureBlobStorage>
			type : string (required)
				The platform type where the system should store the inference results. Set "AzureBlobStorage". *Connector would be initial setting if type is "".
			url : string (required)
				Connection string for Azure Blob Storage.
			name : string (required)
				The name of Azure BlobStorage Container.
		<One of type : AWSS3>
			type : string (required)
				The platform type where the system should store the inference results. Set "AWSS3". *Connector would be initial setting if type is "".
			secret_access_key : string (required)
				The value of AWS secret access key for writing into the destination bucket.
			access_key : string (required)
				The value of AWS access key for writing into the destination bucket.    
			name : string (required)
				The namespace of Azure Event Hubs. *To reset the external transfer settings to their default values, specify an empty string ("") for the parameters.
		<One of type : AWSKinesis>
			type : string (required)
				The platform type where the system should store the inference results. Set "AWSKINESIS". *Connector would be initial setting if type is "".
			name : string (required)
				The name of AWS kinesis stream
			secret_access_key : string (required)
				The value of AWS secret access key for writing into the destination Kinesis.
			access_key : string (required)
				The value of AWS access key for writing into the destination Kinesis.
			partition_key : string (required)
				The value of AWS access key for writing into the destination Kinesis.
			region : string
				The value of AWS region key where destination Kinesis is at.
		<One of type : Kafka>
			type : string (required)
				The platform type where the system should store the inference results. Set "Kafka". *Connector would be initial setting if type is "".
			name : string (required)
				The name of the Kafka topic to publish telemetries
			bootstrap_servers : string (required)
				The list of Kafka endpoints the service could reach. At least two are recommended.
			username : string
				Username to authenticate
			password : string
				The password for the given username.
			client_id : string
				Optional value used to categorize or identify the source of messages, providing additional traceability on the client side.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0196001  
				  Bad request.  
				- E.SC.API.0196002  
				  Invalid parameter name.  
				- E.SC.API.0196003  
				  Invalid parameter url.  
				- E.SC.API.0196005  
				  Invalid parameter Invalid parameter type.   
				- E.SC.API.0196006  
				  The specified IR Hub Connector has already been registered.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0196004  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/connector/ir_hub', headers=headers, method='PUT', payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def GetStorageConnector(self):
        """
		Get the storage hub connectors.

		Returns:
		------------------------------
		[200] Successful Response:
			input_image :  (required)
			inference_result :  (required)
		[401] Authorization Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[403] Forbidden:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[422] Unprocessable entity:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[429] Too Many Requests:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000014  
				  Too Many Requests.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[500] Internal Server Error:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000001  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
		[503] Service Unavailable:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-dd'T'HH:mm:ssXXX.
        """
        headers = self.InitHeaderParam()
        ret = self.Request(url='/connector/storage', headers=headers, method='GET')
        return ret

    @debug_print
    def UpdateStorageConnector(self, payload=None, grant_type:str=None):
        """
		Updates the storage hub connector. Specify the items (inference results, images, or both) to transfer to a storage service.
		To change the transmission destination of inference results, please modify the value of UploadMethodIR in the Command parameter.
		You can store inference results in your cloud storage by setting the value of UploadMethodIR to "BlobStorage".
		Likewise, to revert the transmission to AITRIOS internal storage, set the value of UploadMethodIR to "Mqtt".

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		<One of type : Azure>
			type : string
				The storage service type. Specify “AZURE” as the value. 
				- Value definition:  
				  AZURE
			mode : integer
				Specifies the input image, inferences result or both to be streamed. 
				- Value definition:  
				  0: input image only  
				  1: input image and inference result  
				  2: inference result only
			endpoint : string
				Destination Azure Blob Storage endpoint.  
				*Please do not set “endpoint”, “connection_string”, or “container_name” when returning to the initial value. In the case of the initial value when input image is specified in “mode”, it will be streamed within this service and then when inference result is specified in “mode”, the settings for inference are deleted.
			connection_string : string
				Connection string for Azure Blob Storage.  
				*When initializing, see the description of “endpoint”.  
			container_name : string
				Container name of Azure Blob Storage.  
				*When initializing, see the description of “endpoint”.  
		<One of type : AWS>
			type : string (required)
				The storage service type. Specify “AWS” as the value.  
				- Value definition:  
				  AWS
			mode : integer
				The mode. Specifies the input image , inference result, or both to be streamed. 
				- Value definition:  
				  0: input image only  
				  1: input image and inference result  
				  2: inference result only
			endpoint : string (required)
				Destination AWS S3 endpoint.  
			region : string (required)
				AWS Region. *Need to choose from the official list.  
			bucket_name : string (required)
				AWS S3 Bucket name.  
			secret_access_key : string (required)
				AWS Secret Access key.  
			access_key_id : string (required)
				AWS Access key ID.  

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0195002  
				  Invalid parameter endpoint.  
				- E.SC.API.0195003  
				  Invalid parameter connection_string.  
				- E.SC.API.0195004  
				  Invalid parameter mode.  
				- E.SC.API.0195005  
				  Invalid parameter container_name.  
				- E.SC.API.0195007  
				  Invalid parameter type.  
				- E.SC.API.0195008  
				  Invalid parameter endpoint.  
				- E.SC.API.0195009  
				  Invalid parameter region.  
				- E.SC.API.0195010  
				  Invalid parameter bucket_name.  
				- E.SC.API.0195011  
				  Invalid parameter access_key_id.  
				- E.SC.API.0195012  
				  Invalid parameter secret_access_key.  
				- E.SC.API.0195013  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
				- E.SC.API.0195001  
				  Bad request.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[415] Unsupported Media Type:
			result : string (required)
				ERROR
			code : string (required)
				Error code.
			message : string (required)
				The error message details or the reason.
				[MessageList] *The message for each code is shown below.  
				- E.SC.API.0000016  
				  Unsupported media type.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0195006  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'application/json'})
        ret = self.Request(url='/connector/storage', headers=headers, method='PUT', payload=payload, grant_type=grant_type)
        return ret

    @debug_print
    def UploadFile(self, payload, grant_type:str=None):
        """
		Returns the parameter (file ID) used by the API below. Specify the returned 'file_info.id' as the parameter.
		  - ImportBaseModel
		  - CreateFirmware
		  - ImportEdgeApp

		Parameters:
		------------------------------
		grant_type : str
			The authentication grant type.
			Default value : client_credentials

		Payload:
		------------------------------
		type_code : string
			File type code.
			Enum:
				'non_converted_model'
				'converted_model'
				'input_format_param'
				'network_config'
				'firmware'
				'edge_app'
				'edge_app_dtdl'
				'edge_app_pkg'
				'dcpu_firmware'
				'dcpu_manifest'
				'dcpu_postprocess'
				'model_bundle'
		file : string
			File contents.

		Returns:
		------------------------------
		[200] Successful Response:
			result : string (required)
				SUCCESS
			file_info : object (required)
				The file info.
				file_id : string
					The file ID.
				name : string
					The file name.
				type_code : string
					The file type code.
					Enum:
						'non_converted_model'
						'converted_model'
						'input_format_param'
						'network_config'
						'firmware'
						'edge_app'
						'edge_app_dtdl'
						'edge_app_pkg'
						'dcpu_firmware'
						'dcpu_manifest'
						'dcpu_postprocess'
						'model_bundle'
				size : integer
					The file size.
		[400] Bad Request:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000006  
				  Bad request.  
				- E.SC.API.0199001  
				  Parameter type_code is not set.  
				- E.SC.API.0199002  
				  Invalid parameter type_code.  
				- E.SC.API.0199003  
				  Parameter file is not set.  
				- E.SC.API.0199004  
				  File size over limit.  
				- E.SC.API.0199006  
				  File name too long.  
				- E.SC.API.0199007  
				  Invalid file name.  
				- E.SC.API.0199008  
				  Invalid json format.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[401] Authorization Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000002  
				  Not signed in.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[403] Forbidden:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000003  
				  Unauthorized user.  
				- E.SC.API.0000004  
				  Incorrect permissions.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[404] Not Found:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000013  
				  Not found.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[422] Unprocessable entity:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000007  
				  Json format is invalid.  
				- E.SC.API.0000008  
				  Invalid parameter.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[500] Internal Server Error:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000001  
				  Internal server error.  
				- E.SC.API.0199005  
				  Internal server error.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
		[503] Service Unavailable:
			result : string (required)
				ERROR or WARNING.
			code : string (required)
				Error code.
			message : string (required)
				Error message indicating the cause or details. 
				[MessageList] *The message for each code is shown below:  
				- E.SC.API.0000005  
				  Service is temporarily unavailable.  
			time : string (required)
				The time the error occurred.* yyyy-MM-ddTHH:mm:ss.SSSSSS+00:00.
        """
        headers = self.InitHeaderParam()
        headers.update({'Content-Type':'multipart/form-data'})
        ret = self.Request(url='/files', headers=headers, method='POST', payload=payload, grant_type=grant_type)
        return ret

    ##################################################################
    # Manually added functions from here:
    ##################################################################

    ##################################################################
    #
    # SetDevice
    #   params  : 'device_info_json' device info json file (required)
    #
    #   comment : set device from device info json file
    #
    ##################################################################
    def SetDevice(self, device_info_json):
        Utils.DebugOut(inspect.currentframe().f_code.co_name + ' : ' + device_info_json)

        status = 'SUCCESS'
        if not os.path.exists(device_info_json):
            return 'FAILED : no ' + device_info_json + ' file.'

        f = open(device_info_json, 'r')
        json_load = json.load(f)
        if 'device_id' in json_load:
            self.DEVICE_ID = json_load['device_id']
            device = self.GetDevice(device_id=self.DEVICE_ID)
            if 'result' in device:
                status = 'FAILED. ' + self.DEVICE_ID + ' doesn\'t exist.'
            else:
                if 'property' in device:
                    if 'device_name' in device['property']:
                        self.DEVICE_NAME = device['property']['device_name']
                elif 'device_name' in device:
                    self.DEVICE_NAME = device['device_name']
        elif 'device_name' in json_load:
            self.DEVICE_NAME = json_load['device_name']
            # look for device id
            for device in self.GetDevices()['devices']:
                # for V1
                if 'property' in device:
                    if device["property"]['device_name'] == self.DEVICE_NAME:
                        self.DEVICE_ID = device["device_id"]
                # for V2
                if 'device_name' in device:
                    if device['device_name'] == self.DEVICE_NAME:
                        self.DEVICE_ID = device["device_id"]
            if self.DEVICE_ID == None:
                status = 'FAILED. No device id named ' + self.DEVICE_NAME +  '.'
        else:
            status = 'FAILED. No device_id or device_name in device info json file.'
        f.close()
        return status

    def ListConnectedDevices(self):
        Utils.DebugOut(inspect.currentframe().f_code.co_name)
        ret = self.GetDevices()

        dev_count=1
        for item in ret['devices']:
            if 'connection_state' in item:
                connection_state = item['connection_state']
                if connection_state == 'Connected':
                    device_id = item["device_id"]
                    device_name = item['device_name']
                    print(str(dev_count) + ": " + device_id + ", " + device_name)
                    dev_count += 1

    def DeleteAllImages(self, device_id):
        Utils.DebugOut(inspect.currentframe().f_code.co_name)
        # delete all images taken by the DEVICE_ID
        ret = self.GetImageDirectories(device_id=device_id)
        for devices in ret:
            for device in devices['devices']:
                if device['device_id'] == device_id:
                    sub_folders = device['Image']
                    for sub_folder in sub_folders:
                        print('Delete images in ' + sub_folder)
                        payload = {
                            'directory_deletion': '1',
                        }
                        ret = self.DeleteImages(device_id=device_id, sub_directory_name=sub_folder, payload=payload)
                        if ret['result'] != 'SUCCESS':
                            print(ret)
        print('Done.')
        return 'SUCCESS'

    def DeleteAllInferenceResults(self, device_id):
        Utils.DebugOut(inspect.currentframe().f_code.co_name)
        # delete all inference results taken by the DEVICE_ID

        ret = self.Retrievealistofinferences(devices=device_id)
        inferences = ret['inferences']
        id_list = str([item['id'] for item in inferences]).replace("'","").replace("[","").replace("]","").replace(" ","")
        if id_list != '':
            ret = self.DeleteInferenceResults(device_id=device_id, item_ids=id_list, include_deleted_device=True)
        print('Done.')
        return
    
    def SaveImage(self, name, image, sub_dir):
        try:
            # save image
            os.makedirs("output/" + self.DEVICE_NAME + "/" + sub_dir, exist_ok=True)
            filename = "output/" + self.DEVICE_NAME + "/" + sub_dir + "/"  + name
            cv2.imwrite(filename, image)
            return filename
        except Exception as error:
            return str(error)

    def UpdateProcessState(self, device_id, process_state):

        # get module_id from the device
        device = self.GetDevice(device_id=device_id)
        module_id = device['modules'][0]['module_id'] if 'modules' in device and len(device['modules']) > 0 else None

        configuration_param = self.GetModuleProperty(device_id=device_id, module_id=module_id)
        configuration_param["configuration"]["edge_app"]["common_settings"]["process_state"] = process_state
        ret = self.UpdateModuleConfiguration(device_id=self.DEVICE_ID, module_id=module_id, payload=configuration_param)

    def StartEdgeApp(self, device_id):
        Utils.DebugOut(inspect.currentframe().f_code.co_name)
        self.UpdateProcessState(device_id=device_id, process_state=2)

    def StopEdgeApp(self, device_id):
        Utils.DebugOut(inspect.currentframe().f_code.co_name)
        self.UpdateProcessState(device_id=device_id, process_state=1)


    ##################################################################
    # Device commands
    ##################################################################

    def direct_get_image(self, device_id):
        """
        Directly retrieves an image from the device.
        """
        payload = {
            'command_name': 'direct_get_image',
            'parameters': {
            }
        }

        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret


    def factory_reset(self, device_id):
        """
        Resets the device specified in the self to factory settings.
        """

        payload = {
            'command_name': 'factory_reset',
            'parameters': {}
        }

        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret


    def reboot(self, device_id):
        """
        Reboots the device.
        """

        payload = {
            'command_name': 'reboot',
            'parameters': {}
        }

        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret

    def read_sensor_register(self, device_id, address, size):
        """
        Reads a specific sensor register from the device.
        """
        payload = {
            'command_name': 'read_sensor_register',
            'parameters': {
                'register': [
                    {
                        'address': address,
                        'size': size
                    }
                ]
            }
        }
        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret

    def read_sensor_registers(self, device_id, register):
        """
        Reads a specific sensor register from the device.
        """
        payload = {
            'command_name': 'read_sensor_register',
            'parameters': {
                'register': register
            }
        }
        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret

    def shutdown(self, device_id):
        """
        Shuts down the device.
        As of now (June 2025), this command is not supported in AITRIOS console.
        """

        payload = {
            'command_name': 'shutdown',
            'parameters': {}
        }

        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret

    def write_sensor_register(self, device_id, address, size, value):
        """
        Writes a specific value to a sensor register on the device.
        """
        payload = {
            'command_name': 'write_sensor_register',
            'parameters': {
                'register': [
                    {
                        'address': address,
                        'size': size,
                        'value': value
                    }
                ]
            }
        }
        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret

    def write_sensor_registers(self, device_id, register):
        """
        Writes specific values to sensor registers on the device.
        """
        payload = {
            'command_name': 'write_sensor_register',
            'parameters': {
                'register': register
            }
        }
        ret = self.ExecuteDeviceCommand(
            device_id=device_id,
            payload=payload
        )
        return ret

if __name__ == '__main__':
    args = sys.argv

    project_json = args[1] if len(args) > 1 else None
    device_info_json = args[2] if len(args) > 2 else None

    if len(args) >= 2:
        # Project information
        if not os.path.exists(project_json):
            print('FAILED : no ' + project_json + ' file.')
            sys.exit()

        console = AitriosConsole(project_json=project_json)
        api_version = console.GetApiVersion()
        Utils.DebugOut('AITRIOS Console API Version:' + api_version)

    # Sample for listing connected devices
    if len(args) == 2:
        major_version = api_version.split(".")[0]

        if major_version == "2":
            # V2 API
            devices = console.GetDevices(connection_state='Connected')['devices']
            device_names = [item['device_name'] for item in devices]
        elif major_version == "1":
            # V1 API
            devices = console.GetDevices(connectionState='Connected')['devices']
            device_names = [item['property']['device_name'] for item in devices]
        else:
            print('API Version : ' + api_version + ' is not supported. V1/V2 API only.')
            sys.exit()
        print('### Connected Devices ###')
        print(json.dumps(device_names, indent=2))

    # Sample for showing device information
    elif len(args) >= 3:
        ret = console.SetDevice(device_info_json=device_info_json)
        print(ret)
        if ret != 'SUCCESS':
            sys.exit()

        # Show device info
        device = console.GetDevice(device_id=console.DEVICE_ID)
        print('### Device info ###')
        print(json.dumps(device, indent=2))

    else:
        print('#####################################################################')
        print('# AitriosConsole.py')
        print('#')
        print('#   params  : \'project_json\' : project json file (required)')
        print('#   params  : \'device_info_json\' : device info json file')
        print('#')
        print('#####################################################################')
