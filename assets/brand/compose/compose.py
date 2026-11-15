"""Build the avatar, social preview and banner from the mascot artwork (unchanged).
Run via assets/brand/compose/build.sh."""
import os, sys
import numpy as np
from PIL import Image, ImageFilter, ImageDraw
HERE=os.path.dirname(os.path.abspath(__file__)); BRAND=os.path.dirname(HERE); WORK=sys.argv[1]
src=Image.open(os.path.join(BRAND,'mascot','redfilade-mascot.png')).convert('RGB')
def scene(W,H,img_h,img_x,teal=True):
    sc=img_h/src.height; im=src.resize((round(src.width*sc),img_h),Image.LANCZOS)
    a=np.asarray(im).astype(np.float32)
    # extend: stretch the right edge column across, and the left edge column to the left
    canvas=np.zeros((H,W,3),np.float32)
    y0=(H-img_h)//2
    right=a[:,-6:,:].mean(axis=1,keepdims=True); left=a[:,:6,:].mean(axis=1,keepdims=True)
    canvas[y0:y0+img_h,:img_x]=left; canvas[y0:y0+img_h,img_x:]=right
    # blend the image in with feathered left/right edges
    fw=70; ramp=np.ones(im.width,np.float32); ramp[:fw]=np.linspace(0,1,fw); ramp[-fw:]=np.linspace(1,0,fw)
    if img_x<=0: ramp[:fw]=1
    seg=canvas[y0:y0+img_h,img_x:img_x+im.width]; w=ramp[None,:,None][:, :seg.shape[1]]
    canvas[y0:y0+img_h,img_x:img_x+im.width]=seg*(1-w)+a[:, :seg.shape[1]]*w
    out=Image.fromarray(canvas.clip(0,255).astype(np.uint8))
    # soften the stretched area so streaks disappear (keep the mascot sharp)
    blurred=out.filter(ImageFilter.GaussianBlur(18)); mask=Image.new('L',(W,H),255); d=ImageDraw.Draw(mask)
    d.rectangle([img_x+fw,0,img_x+im.width-fw,H],fill=0); mask=mask.filter(ImageFilter.GaussianBlur(30))
    out=Image.composite(blurred,out,mask)
    if teal:
        g=np.zeros((H,W,1),np.float32); yy,xx=np.mgrid[0:H,0:W]
        cx,cy=W*0.93,H*0.12; r=np.hypot(xx-cx,yy-cy)/(max(W,H)*0.55); g[...,0]=np.clip(1-r,0,1)**2*0.22
        o=np.asarray(out).astype(np.float32); o=o*(1-g)+np.array([40,175,180])*g
        out=Image.fromarray(o.clip(0,255).astype(np.uint8))
    return out
scene(1280,640,640,60).save(os.path.join(WORK,'bg_social.png'))
scene(1600,520,520,170).save(os.path.join(WORK,'bg_banner.png'))
# avatar: head and upper body, square
src.crop((108,96,108+880,96+880)).resize((1024,1024),Image.LANCZOS).save(os.path.join(BRAND,'redfilade-avatar-1024.png'))

