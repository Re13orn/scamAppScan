import uuid
import pathlib
import os

class Config(object):
    SECRET_KEY = str(uuid.uuid4())
    API_TOKEN = "c7a65f9847a138f076ff88cb00aa68b3bc010759b1317167002ebd4ed58a8e8b"
    UPLOAD_FOLDER = pathlib.Path(__file__).parent.joinpath('upload').resolve()
    if not os.path.isdir(UPLOAD_FOLDER):
        os.mkdir(UPLOAD_FOLDER)
    
    UPLOAD_FOLDER_JSON = os.path.join(UPLOAD_FOLDER, 'json')
    if not os.path.isdir(UPLOAD_FOLDER_JSON):
        os.mkdir(UPLOAD_FOLDER_JSON)

    UPLOAD_FOLDER_APK = os.path.join(UPLOAD_FOLDER, 'apk')
    if not os.path.isdir(UPLOAD_FOLDER_APK):
        os.mkdir(UPLOAD_FOLDER_APK)
    