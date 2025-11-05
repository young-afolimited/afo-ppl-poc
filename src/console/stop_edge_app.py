import os
import sys
from aitrios.AitriosConsole_V2 import AitriosConsole

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

    else:
        print('##########################################################')
        print('# USAGE')
        print('# ')
        print('# ' + str(args[0]) + ' <param:1-2>')
        print('#     <param:1> : Required <project json file>')
        print('#     <param:2> : Required <device json file>')
        print('##########################################################')
        sys.exit()

    # stop edge app
    console.StopEdgeApp(device_id=console.DEVICE_ID)
