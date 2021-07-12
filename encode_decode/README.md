## Enclave 中进行生成密钥并加密解密随机数
1. 新建支持enclave功能的ec2 instance  
2. 安装nitro-cli包  
```bash
sudo amazon-linux-extras install aws-nitro-enclaves-cli  
sudo yum install aws-nitro-enclaves-cli-devel -y  
sudo usermod -aG ne ec2-user  
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service  
sudo amazon-linux-extras install docker  
sudo systemctl start docker  
sudo systemctl enable docker  
sudo usermod -a -G docker ec2-user  
sudo systemctl start docker && sudo systemctl enable docker  
sudo amazon-linux-extras enable aws-nitro-enclaves-cli  
sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel   
```
3.打开/etc/nitro_enclaves/allocator.yaml，修改可分配的memory  
```bash
# memory_mib: 512  
memory_mib: 3000   
```  
4. 再运行  
```bash    
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service   
sudo systemctl start docker && sudo systemctl enable docker   
```
5. Reboot 你的 instance   
   
6.   
```bash   
yum install git    
git clone -b encode_decode https://github.com/hyoer0423/nitro-enclave-python-demo.git    
```
7. 进入server文件夹   
```bash    
cd nitro-enclave-python-demo/encode_decode/server   
chmod +x build.sh  
sudo ./build.sh   
```   
当enclave 创建完毕，会出现  
```bash   
Enclave Image successfully created.  
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "fdd6b3c0e70ee927046ab974521362a7534a629fdccb195abc69147a133b27b8233ff9153b376af2dccf9503cb43246e",
    "PCR1": "c35e620586e91ed40ca5ce360eedf77ba673719135951e293121cb3931220b00f87b5a15e94e25c01fecd08fc9139342",
    "PCR2": "951c4c27d03d0777288f7de339abdd0640da15d454e0efbe8e29bac74a8e8ea06edda8401b6bb672b1b71d32b9bf6751"
  }
}
Start allocating memory...
Started enclave with enclave-cid: 16, memory: 2600 MiB, cpu-ids: [1, 17]
{
  "EnclaveID": "i-097a9a35e16a8962c-enc17a99614bf41bf8",
  "ProcessID": 7194,
  "EnclaveCID": 16,
  "NumberOfCPUs": 2,
  "CPUIDs": [
    1,
    17
  ],
  "MemoryMiB": 2600
}
```
请记录下您的**EnclaveCID**  
8.再打开一个instance 窗口，运行**vsock-proxy** 工具  
```bash
vsock-proxy 8000 kms.us-east-1.amazonaws.com 443  
```   
9. 进入client文件夹    
cd nitro-enclave-python-demo/encode_decode/client    
10.下载相关包并运行文件     
```bash     
yum install python3 -y
python3 -m venv venv
source venv/bin/activate
sudo pip3 install -r requirements.txt
sudo python3 client.py [EnclaveCID]
```
  