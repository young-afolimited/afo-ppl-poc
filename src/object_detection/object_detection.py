import os
import json
import sys
import base64
import cv2
from src.SmartCamera import ObjectDetectionTop
from src.SmartCamera import BoundingBox
from src.SmartCamera import BoundingBox2d

def decode_object_detection(json_data, label_file):

    if not json_data:
        return 0, False

    # get label information
    with open(label_file, 'r', encoding='utf-8') as label:
        items = label.read().splitlines()

    # pick inference result
    # for http storage
    inference_result = None
    if json_data.get('Inferences'):
        inference_result = json_data['Inferences'][0]
    elif json_data.get('inferences'):
        inference_result = json_data['inferences'][0]
    else:
        return 0, False, 'no inference key in this data'

    # Base64 decode
    if 'O' in inference_result:
        buf_decode = base64.b64decode(inference_result['O'])
    else:
        return 0, False, 'not inference result in this data'

    # Deserialize
    ppl_out = ObjectDetectionTop.ObjectDetectionTop.GetRootAsObjectDetectionTop(buf_decode, 0)
    obj_data = ppl_out.Perception()
    res_num = obj_data.ObjectDetectionListLength()

    # Check detection
    if res_num > 0:
        # generate json
        inference_result.pop('O')
        for i in range(res_num):
            obj_list = obj_data.ObjectDetectionList(i)
            union_type = obj_list.BoundingBoxType()
            if union_type == BoundingBox.BoundingBox.BoundingBox2d:
                bbox_2d = BoundingBox2d.BoundingBox2d()
                bbox_2d.Init(obj_list.BoundingBox().Bytes, obj_list.BoundingBox().Pos)
                inference_result[str(i + 1)] = {}
                inference_result[str(i + 1)]['C'] = items[obj_list.ClassId()]
                inference_result[str(i + 1)]['P'] = obj_list.Score()
                inference_result[str(i + 1)]['X'] = bbox_2d.Left()
                inference_result[str(i + 1)]['Y'] = bbox_2d.Top()
                inference_result[str(i + 1)]['x'] = bbox_2d.Right()
                inference_result[str(i + 1)]['y'] = bbox_2d.Bottom()
        return res_num, inference_result
    else:
        return 0, False
    
def overlay_object_detection(image, num, inference):
    try:
        for i in range(num):
            x = inference[str(i + 1)]['X']
            y = inference[str(i + 1)]['Y']
            width = inference[str(i + 1)]['x'] - x
            height = inference[str(i + 1)]['y'] - y
            label = str(inference[str(i + 1)]['C']) + ":" + "{:.1f}%".format(inference[str(i + 1)]['P']*100)
            font = cv2.FONT_HERSHEY_SIMPLEX
            font_scale = 0.4
            font_thickness = 1

            cv2.rectangle(image, (x, y), (x + width, y + height), (0, 255, 0), 2)

            (text_width, text_height), baseline = cv2.getTextSize(label, font, font_scale, font_thickness)
            background_top_left = (x, y)
            background_bottom_right = (x + text_width, y + text_height + baseline)
            cv2.rectangle(image, background_top_left, background_bottom_right, (0, 255, 0), cv2.FILLED)
            cv2.putText(image, label, (x, y + text_height + int(baseline/2)), font, font_scale, (0, 0, 0), font_thickness, cv2.LINE_AA)
    except Exception as e:
        print(f"Error: {e}")
    return image

def draw_object_detection(image_file:str, metadata_file:str):
    try:
        image = cv2.imread(image_file)

        if os.path.exists(image_file):
            with open(metadata_file) as file:
                metadata = json.load(file)

            num,inference = decode_object_detection(json_data=metadata, label_file='object_detection/class_definition_file/class80.txt')
            if num > 0:
                print(json.dumps(inference, indent=2, ensure_ascii=False))

            # create overlay image
            over_lay_image = overlay_object_detection(image, num=num, inference=inference)
        else:
            over_lay_image = image # no overlay if image file does not exist

        # Open viewer
        if over_lay_image is not None and over_lay_image.size > 0:
            cv2.imshow("Viewer", over_lay_image)
            cv2.waitKey(1)

    except Exception as e:
        print(f"Error in draw_object_detection: {e}")
        return None
    return over_lay_image

if __name__ == '__main__':
    args = sys.argv
    json_data=args[1]
    label_file=args[2]

    res_num, inference_result = decode_object_detection(json_data, label_file)
    print(inference_result)
