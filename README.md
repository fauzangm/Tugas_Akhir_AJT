## TUGAS AKHIR ARISTEKTUR JARINGAN TERKINI 

# Table Of Contents

- [MEMBUAT EC2 INSTANCE di AWS ACADEMY](#membuat-ec2-instance-di-aws-academy)
- [MEMBUAT CUSTOM TOPOLOGY MININET SEPERTI PADA TUGAS2](#membuat-custom-topology-mininet-seperti-pada-tugas2)
- [MEMBUAT APLIKASI RYU LOAD BALANCER SEPERTI PADA TUGAS 3](#membuat-aplikasi-ryu-load-balancer-seperti-pada-tugas-3)




## MEMBUAT EC2 INSTANCE di AWS ACADEMY
Pada Ketentuan tugas Kita akan membuat akun EC2 INSTANCE dengan spesifikasi sebagai berikut
- Name and tags	= Tugas Akhir
- OS Images	= Ubuntu Server 22.04 LTS 64 bit
- Instance type	= t2.medium
- Key pair	= vockey
- Edit Network settings	= allow SSH, allow HTTP, allow HTTPS, allow TCP port 8080, allow TCP port 8081
- Configure storage	= 30 GiB, gp3


![Screenshot from 2022-06-07 13-40-04](https://user-images.githubusercontent.com/83495936/172538348-95fb5e09-5cbb-47da-95aa-714586f75dc0.png)


![Screenshot from 2022-06-07 13-40-13](https://user-images.githubusercontent.com/83495936/172538546-d7891727-138a-4c47-a70c-eee8fcbe9c04.png)


![Screenshot from 2022-06-07 13-40-20](https://user-images.githubusercontent.com/83495936/172538590-c31be9e6-cef6-438d-b786-6227f6ddacb2.png)

![Screenshot from 2022-06-07 13-40-34](https://user-images.githubusercontent.com/83495936/172538607-85841ed0-52c9-4f0e-bb06-cc9c17ff6dd3.png)

![Screenshot from 2022-06-07 13-40-37](https://user-images.githubusercontent.com/83495936/172538637-555f1387-4f73-4fc1-958e-c475d21e7354.png)

![Screenshot from 2022-06-07 13-41-10](https://user-images.githubusercontent.com/83495936/172538678-635fde78-47df-4748-8147-21a8eb170b09.png)

- ### Setelah Selesai Melakukan Konfigurasi EC2, Saya akan menghubungkannya dengan terminal ubuntu
<br> Dengan melakukan perintah ssh -i labsuser.pem ubuntu@ipaddress </br>

![Screenshot from 2022-06-07 13-54-32](https://user-images.githubusercontent.com/83495936/172539424-5be6a254-6bb1-4a45-aff5-fc7117841a47.png)

- ### Setelah EC2 Instance siap, Selanjunta instalasi Mininet+OpenFlow, Ryu
<br> Langkah Pertama dengan mengupdate dan mengupgrade server ubuntu dengan perintah sudo apt -yy update && sudo apt -yy upgrade  </br>


![Screenshot from 2022-06-07 13-57-27](https://user-images.githubusercontent.com/83495936/172539980-c9303556-870e-4a19-906d-f29122ec253f.png)


<br> Langkah Kedua Unduh repository Mininet dengan perintah git clone https://github.com/mininet/mininet  dan lakukan instalasi dengan perintah mininet/util/install.sh -nfv </br>

<br> Langkah Ketiga Unduh repository RYU dengan perintah git clone https://github.com/mininet/mininet  dan lakukan instalasi dengan perintah cd ryu; pip install </br>

<br> Langkah Keempat Unduh repository Flow Manager dengan perintah git clone https://github.com/martimy/flowmanager  setelah selesai kita cek dengan perintah ls </br>



![Screenshot from 2022-06-07 14-06-25](https://user-images.githubusercontent.com/83495936/172542516-8d7b9a65-31a8-4931-9a5c-857d747a7d60.png)

## MEMBUAT CUSTOM TOPOLOGY MININET SEPERTI PADA TUGAS2

- ### Topolgy yang digunakan



- ### Program yang digunakan


- ### Setelah itu akan menjalankan mininet tanpa controller menggunakan custom topo yang sudah dibuat
<br> Lakukan dengan perintah sudo mn --controller=none --custom custom_topo_2sw2h.py --topo mytopo --mac --arp


- ### Membuat Flow agar h1,h2 dan h3 saling terhubung dengan perintah 


- ### Melakuka Uji Koneksi


## MEMBUAT APLIKASI RYU LOAD BALANCER SEPERTI PADA TUGAS 3


- ### Topolgy yang digunakan




