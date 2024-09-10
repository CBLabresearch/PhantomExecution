# PhantomExecution
![](https://github.com/user-attachments/assets/4578b633-0874-433e-8011-fdddc3330f9f)

> Self Cleanup in post-ex job, suit for CobaltStrike 



When the target of process injection is the current process, and when the post-ex job is executed and the thread exits, the memory will look like this

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/imagesimage-20240910183625105.png)

Then, perform 5 screenshots:

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/imagesimage-20240910183718333.png)

So, we use the RDI  itself to clean up itself and the memory area  which the post-ex job is executed.

This is also a general memory execution plugin

![](https://images-1258433570.cos.ap-beijing.myqcloud.com/imagesimage-20240910184202951.png)

The code is not beautiful, and many IOCs are not evasioned. Please modify it according to OPSEC principles. This code only shows the self clean technology.



writeup: https://mp.weixin.qq.com/s/V4EdhGzyzxln0LzU99hqpA

conference: https://github.com/knownsec/KCon/blob/master/2024/%E9%AB%98%E7%BA%A7%E6%81%B6%E6%84%8F%E8%BD%AF%E4%BB%B6%E5%BC%80%E5%8F%91%E4%B9%8BRDI%E7%9A%84%E8%BF%9B%E5%8C%96.pdf
