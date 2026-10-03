detect.tflite + labelmap.txt: Google's COCO SSD MobileNet v1 (quantized, 2018-06-29), from
https://storage.googleapis.com/download.tensorflow.org/models/tflite/coco_ssd_mobilenet_v1_1.0_quant_2018_06_29.zip
(downloaded by the owner and attached to the project, 2026-10-03; zip sha256 a809cd29...b6dc,
detect.tflite sha256 e4b118e5...9d13). Verified locally: 300x300 uint8 input, 10 detections; finds person/cat/cup
on test images. Apache-2.0 (TensorFlow models).
