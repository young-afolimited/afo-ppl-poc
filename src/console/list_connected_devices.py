import sys
from aitrios.AitriosConsole_V2 import AitriosConsole

if __name__ == '__main__':

    args = sys.argv
    arg_num = len(args)

    if arg_num == 2:
        console = AitriosConsole(project_json=args[1])

        # get Console API version
        ret = console.GetApiVersion()
        print("AITRIOS Console API Version=" + ret)

    else:
        print('##########################################################')
        print('# USAGE')
        print('# ')
        print('# ' + str(args[0]) + ' <param:1>')
        print('#     <param:1> : Required <project json file>')
        print('##########################################################')
        sys.exit()

    console.ListConnectedDevices()
