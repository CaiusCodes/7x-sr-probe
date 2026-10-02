package com.zeekr.sdk.adcu.bean;

/** Stand-in with the shape a perception object might have; only its NAMES are read by the probe. */
public class SRObject implements java.io.Serializable {
    public int id;
    public int type;
    public float posX;
    public float posY;
    public float speed;
    public static final int TYPE_CAR = 1;
    public float getPosX() { return posX; }
    public void setPosX(float v) { posX = v; }
}
