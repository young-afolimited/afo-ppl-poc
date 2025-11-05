import sys
import inspect
import json
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
        
    # delete all images in AITRIOS console
    ret = console.DeleteAllImages(device_id=console.DEVICE_ID)
    if ret != 'SUCCESS':
        sys.exit()

    # delete all inference results in AITRIOS console
    console.DeleteAllInferenceResults(device_id=console.DEVICE_ID)
