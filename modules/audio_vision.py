import cv2, pyaudio, numpy as np, struct

def mic_level():
    try:
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100,
                        input=True, frames_per_buffer=1024)
        data = struct.unpack(str(2*1024)+'B', stream.read(1024, exception_on_overflow=False))
        level = np.average(np.abs(np.array(data))) / 255
        stream.stop_stream(); stream.close(); p.terminate()
        return round(level * 100, 2)
    except Exception:
        return 0.0

def capture_frame():
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    cam.release()
    if not ret:
        return None
    _, buffer = cv2.imencode(".jpg", frame)
    return buffer.tobytes()
