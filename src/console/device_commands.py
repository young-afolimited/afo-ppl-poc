import sys
import cv2
import io
from PIL import Image
import numpy as np
from aitrios.utils import Utils
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

    Utils.DebugOut("Read single register test")
    ret = console.read_sensor_register(console.DEVICE_ID, address=0x0034c, size=2)  # Example address and size
    if ret['result'] == 'SUCCESS':
        ret = Utils.Dec2Hex(ret['command_response']['register'][0])
    print(f"Sensor Register Value: {ret}")

    Utils.DebugOut("Write single sensor register test")
    ret = console.write_sensor_register(console.DEVICE_ID, address=0x0034c, size=2, value=0x0)  # Example address and value
    print(f"Write Sensor Register Response: {ret}")
    ret = console.write_sensor_register(console.DEVICE_ID, address=0x0034e, size=2, value=0)  # Example address and value
    print(f"Write Sensor Register Response: {ret}")

    Utils.DebugOut("Read multiple sensor registers test")
    register = [{'address': 0x0034c, 'size': 2}, {'address': 0x0034e, 'size': 2}]
    ret = console.read_sensor_registers(console.DEVICE_ID, register=register)  # Read back to verify
    if ret['result'] == 'SUCCESS':
        for reg in ret['command_response']['register']:
            ret = Utils.Dec2Hex(reg)
            print(f"Read Sensor Registers Response: {ret}")
    else:
        print("Failed to read sensor registers:", ret)

    Utils.DebugOut("Write multiple sensor registers test")
    register = [{'address': 0x0034c, 'size': 2, 'value': 0x07ec}, {'address': 0x0034e, 'size': 2, 'value': 0x05F0}]
    ret = console.write_sensor_registers(console.DEVICE_ID, register=register)  # Write multiple registers
    print(f"Write Sensor Registers Response: {ret}")

    Utils.DebugOut("Read multiple sensor registers test")
    register = [{'address': 0x0034c, 'size': 2}, {'address': 0x0034e, 'size': 2}]
    ret = console.read_sensor_registers(console.DEVICE_ID, register=register)  # Read back to verify
    if ret['result'] == 'SUCCESS':
        for reg in ret['command_response']['register']:
            ret = Utils.Dec2Hex(reg)
            print(f"Read Sensor Registers Response: {ret}")
    else:
        print("Failed to read sensor registers:", ret)

    Utils.DebugOut("Direct image test")
    print("Press 'q' to exit the image display window.")
    ret = console.direct_get_image(console.DEVICE_ID)  # Directly get image from the device
    if ret['result'] == 'SUCCESS':
        image = ret['command_response']['image']
        if image:
            # show image
            try:
                dec_response = Utils.Base64Decoder(data=image)
                img_numpy = np.asarray(Image.open(io.BytesIO(dec_response)))
                image = cv2.cvtColor(img_numpy, cv2.COLOR_RGBA2BGR)
                while True:
                    cv2.imshow("Direct Image", image)
                    if cv2.waitKey(1) & 0xFF == ord('q'):
                        cv2.destroyAllWindows()
                        break
            except Exception as e:
                print(f"Error displaying image: {e}")
        else:
            print("No image data received.")
    else:
        print("Failed to retrieve image:", ret)

    Utils.DebugOut("Reboot command test")
    ret = console.reboot(console.DEVICE_ID)  # Reboot the device
    print(f"Reboot Response: {ret}")

    # As of now (June 2025), shutdown command is not supported in AITRIOS console.
#    Utils.DebugOut("Shutdown command test")
#    ret = console.shutdown(console.DEVICE_ID)  # Shutdown the device
#    print(f"Shutdown Response: {ret}")
