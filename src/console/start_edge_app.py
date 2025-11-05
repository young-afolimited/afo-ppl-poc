import sys
import json
from console.aitrios.AitriosConsole_V2 import AitriosConsole
from object_detection.object_detection import decode_object_detection

if __name__ == '__main__':

    args = sys.argv
    arg_num = len(args)

    configuration_param = None

    if arg_num >= 3:
        console = AitriosConsole(project_json=args[1])

        # get Console API version
        ret = console.GetApiVersion()
        print("AITRIOS Console API Version=" + ret)

        ret = console.SetDevice(device_info_json=args[2])
        print(ret)
        if ret != 'SUCCESS':
            sys.exit()

        # get module_id from the device
        device = console.GetDevice(device_id=console.DEVICE_ID)
        module_id = device['modules'][0]['module_id'] if 'modules' in device and len(device['modules']) > 0 else None
        print(json.dumps(module_id, indent=2))  # print device info

        # if arg[3] is not provided, get current configuration from the device
        if arg_num < 4:
            configuration_param = console.GetModuleProperty(device_id=console.DEVICE_ID, module_id=module_id)
            #save current configuration as json file
            with open('json/current_configuration.json', 'w') as file:
                json.dump(configuration_param, file, indent=2)
        else:
            # create json object from configuration json file
            try:
                print(f"Reading configuration JSON file: {args[3]}")
                with open(args[3], 'r') as file:
                    configuration_param = json.load(file)
                ret = console.UpdateModuleConfiguration(
                    device_id=console.DEVICE_ID,
                    module_id=module_id,
                    payload=configuration_param
                )
            except Exception as e:
                print(f"Error reading configuration JSON file: {e}")
                sys.exit()

    else:
        print('##########################################################')
        print('# USAGE')
        print('# ')
        print('# ' + str(args[0]) + ' <param:1-2>')
        print('#     <param:1> : Required <project json file>')
        print('#     <param:2> : Required <device json file>')
        print('#     <param:3> : Option <configuration json file>')
        print('##########################################################')
        sys.exit()

    # start edge app
    console.StartEdgeApp(device_id=console.DEVICE_ID)

    # get meta storage location information
    method = configuration_param['configuration']['edge_app']['common_settings']['port_settings']['metadata']['method']
    print('Method: ' + str(method))

    # method :# 0: Upload by using MQTT
    #         # 1: Upload to Blob storage
    #         # 2: Upload local HTTP server
    if method != 2:
        last_timestamp = None
        while True:
            ret = console.Retrievealistofinferences(devices=console.DEVICE_ID)
            # get latest metadaa
            latest = ret['inferences'][-1]
            num,inference = decode_object_detection(json_data=latest, label_file='object_detection/class_definition_file/class80.txt')
            timestamp = inference['T']
            if num > 0 and timestamp != last_timestamp:
                print('###########################################################')
                print(json.dumps(inference, indent=2, ensure_ascii=False))
                last_timestamp = timestamp