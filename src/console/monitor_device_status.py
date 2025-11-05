import sys
from datetime import datetime
from aitrios.AitriosConsole_V2 import AitriosConsole
from aitrios.utils import Utils

if __name__ == '__main__':

    args = sys.argv
    arg_num = len(args)

    if arg_num == 3:
        console = AitriosConsole(project_json=args[1])

        # get Console API version
        ret = console.GetApiVersion()
        print("AITRIOS Console API Version=" + ret)

        ret = console.SetDevice(device_info_json=args[2])
        print(ret)
        if ret != 'SUCCESS':
            sys.exit()
    else:
        print('##########################################################')
        print('# USAGE')
        print('# ')
        print('# ' + str(args[0]) + ' <param:1-2>')
        print('#     <param:1> : Required <project json file>')
        print('#     <param:2> : Required <device json file>')
        print('##########################################################')
        sys.exit()

    while True:
        # get device, sensor status check
        Utils.DebugOut("GetDevice : " + str(datetime.now()))
        ret = console.GetDevice(device_id=console.DEVICE_ID)
        if ret['connection_state'] != 'Connected':
            sys.exit()
        device_id = ret['device_id']
        device_name = ret['device_name']
        connection_state = ret['connection_state']
        process_state_device = ret['property']['state']['device_states']['process_state']
        process_state_config = ret['modules'][0]['property']['configuration']['edge_app']['common_settings']['process_state']
        process_state_app = ret['modules'][0]['property']['state']['edge_app']['common_settings']['process_state']
        print('Device ID             : ' + device_id)
        print('Device Name           : ' + device_name)
        print('Connection state      : ' + connection_state)
        print('Process state.device  : ' + process_state_device)
        print('             .edge_app: ' + str(process_state_app))
        print('             .config  : ' + str(process_state_config))
