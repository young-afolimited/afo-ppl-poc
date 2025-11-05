from fastapi import FastAPI, Request, Response, status
import json
import os.path
import traceback
import logging
from object_detection.object_detection import draw_object_detection

SAVE_PATH_IMG = 'data/image'
SAVE_PATH_META = 'data/meta'

app_ins = FastAPI()

# Log format
log_format = '%(asctime)s - %(message)s'
# Set log level to INFO
logging.basicConfig(format=log_format, level=logging.INFO)
# set to True to save files,
# set to False to not save files
SAVE_FILE = True
device_id = 'dummy'

def save_file(file_type, device_id, content, filename):
    dir_name = os.path.join(file_type, device_id)
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    file_path = os.path.join(dir_name, filename)
    with open(file_path, 'wb') as w_fp:
        w_fp.write(content)
    return file_path


@app_ins.put("/data/meta/{filename}")
async def update_items(filename, request: Request, response: Response):
    try:
        content = await request.body()
        if SAVE_FILE:
            global device_id
            body = json.loads(content)
            device_id = body['DeviceID']
            save_file(SAVE_PATH_META, device_id, content, filename)
            logging.info("Meta File Saved: %s", filename)
        else:
            logging.info("Meta File Not Saved: %s", filename)
        return {"status":status.HTTP_200_OK}
    except (Exception):
        traceback.print_exc()

@app_ins.put("/data/image/{filename}")
async def update_items(filename, request: Request, response: Response):
    try:
        content = await request.body()
        file_path=''
        if SAVE_FILE:
            global device_id
            if not device_id:
                logging.error("DeviceID not set, cannot save image file.")
            else:
                file_path = save_file(SAVE_PATH_IMG, device_id, content, filename)
                logging.info("Image File Saved: %s", filename)
        else:
            logging.info("Image File Not Saved: %s", filename)

        # Open viewer
        # create image data
        if os.path.exists(file_path):
            draw_object_detection(
                image_file=file_path,
                metadata_file=os.path.join(SAVE_PATH_META, device_id, filename.replace('.jpg', '.txt'))
            )

        return {"status":status.HTTP_200_OK}
    except (Exception):
        traceback.print_exc()
