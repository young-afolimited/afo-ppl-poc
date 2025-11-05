import os
import base64
import cv2
from PIL import Image
import numpy as np
import io
import datetime
import json
import re
from datetime import datetime

class Utils():
    @staticmethod
    def Base64Decoder(data):
        if type(data) is str:
            data = data.encode("utf-8")
        decoded_data = base64.decodebytes(data)
        return decoded_data

    @staticmethod
    def Base64EncodedStr(data):
        if type(data) is str:
            data = data.encode("utf-8")
        encoded_data = base64.b64encode(data)
        encoded_str = str(encoded_data).replace("b'","").replace("'","")
        return str(encoded_str)

    @staticmethod
    def BytesToJpg(encoded_image_data, subDir):
        response = Utils.Base64Decoder(encoded_image_data)
        img_numpy = np.asarray(Image.open(io.BytesIO(response)))
        img = cv2.cvtColor(img_numpy, cv2.COLOR_RGBA2BGR)
        os.makedirs("output/" + subDir, exist_ok=True)
        dt_utc_now = datetime.datetime.utcnow()
        now_time_utc = datetime.datetime.strftime(dt_utc_now,'%Y%m%d%H%M%S')
        filename = "output/" + subDir + "/" +  now_time_utc + ".jpg"
        cv2.imwrite(filename, img)
        return filename

    @staticmethod
    def DebugOut(comment):
        print("")
        print("###########################################################################")
        print("# " + comment)
        print("###########################################################################")

    @staticmethod
    def PrintJsonKeys(data,indent=0, is_return=True):
        space = ' '*indent
        if type(data) == dict:
            for k in data.keys():
                print('\n',space,'-',k,end='')
                Utils.PrintJsonKeys(data[k],indent+2, is_return=False)
        elif type(data) == list and len(data) > 0:
            Utils.PrintJsonKeys(data[0],indent, is_return=False)
        if is_return:
            print('\n')

    @staticmethod
    def Dec2Hex(reg: dict):
        """
        Convert decimal address and value to hexadecimal format.
        :param reg: Dictionary with keys 'address', 'size', and 'value'
        :return: Hexadecimal string in the format "0xXXXX: 0xYYYY"
        """
        address = reg.get('address')
        size = reg.get('size')
        value = reg.get('value')

        if size not in [1, 2, 4]:
            raise ValueError("Size must be 1, 2, or 4 bytes.")

        hex_address = f"0x{address:04X}"
        hex_value = f"0x{value:0{size*2}X}"

        return f"{hex_address}: {hex_value}"

    @staticmethod
    def GetLatestFile(directory, extension="txt"):
        pattern = r"^\d{8}\d{6}\d{3}\." + re.escape(extension) + r"$"

        latest_file = None
        latest_time = None

        if not os.path.exists(directory):
            return None
    
        for file_name in os.listdir(directory):
            if re.match(pattern, file_name):
                
                timestamp_str = file_name.split(".")[0]
                file_time = datetime.strptime(timestamp_str, "%Y%m%d%H%M%S%f")
                
                if latest_time is None or file_time > latest_time:
                    latest_time = file_time
                    latest_file = file_name
        return directory + '/' + str(latest_file)

if __name__ == '__main__':
#    test_str = "sid-100A50500A2005038764012000000000"
#    encoded_str = Utils.Base64EncodedStr(test_str)
#    print('encoded_str = ' + encoded_str)
    encoded_str = "DAAAAAAABgAKAAQABgAAAAwAAAAAAAYACAAEAAYAAAAEAAAAAQAAABAAAAAMABAAAAAHAAgADAAMAAAAAAAAARQAAAAAAH8/DAAUAAQACAAMABAADAAAAAEAAAAvAAAA+AAAAC0BAAA="
    ret = Utils.Base64Decoder(encoded_str)
    print(ret)
