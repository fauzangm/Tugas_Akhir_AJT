## TUGAS AKHIR ARISTEKTUR JARINGAN TERKINI 

# Table Of Contents

- [MEMBUAT EC2 INSTANCE di AWS ACADEMY](#membuat-ec2-instance-di-aws-academy)
- [Dynamic Analysis](#dynamic-analysis)
- [Disassembler](#disassembler)
- [Breakpoint](#breakpoint)
- [Register](#register)
- [StackView](#stack-view)
- [Tools Debugger yang digunakan](#tools-debugger-yang-digunakan)
- [Konsep Debugging IDA](#konsep-debugging-ida)
- [Toolbar Dynamic-analysis IDA](#toolbar-dynamic-analysis-ida)



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

- ## Setelah Selesai Melakukan Konfigurasi EC2, Saya akan menghubungkannya denga terminal ubuntu
<br> Dengan melakukan perintah ssh -i labsuser.pem ubuntu@ipaddress </br>

![Screenshot from 2022-06-07 13-54-32](https://user-images.githubusercontent.com/83495936/172539424-5be6a254-6bb1-4a45-aff5-fc7117841a47.png)






## Dynamic Analysis

Dalam Dynamic analysis pengujian program dengan menganalisis dan mengeksekusi program secara real time atau memahami program dengan menjalankannya (Debugging)


## Disassembler
Disassembler hanya akan menampilkan kode dalam assembly dalam bentuk teks yang bisa dibaca manusia.


## Breakpoint
Breakpoint berfungsi untuk mempause program agar bisa menganalisis register / alamat memory dan melihat variabel

## Register
sebuah tempat untuk penampungan sementara  data-data yang akan diolah 
 


## Stack View
Tampilan isi dari stack program dan biasanya variabel local muncul di stack view



## Tools Debugger yang digunakan
- IDA pro


## Konsep Debugging IDA

Karena IDA merupakan aplikasi windows maka diperlukan remote debugging ke server local debugger linux dengan menggunakan port yang disediakan dan alamat hostname menggunakan localhost 127.0.0.1

## Toolbar Dynamic-analysis IDA
Yang paling penting di gunakan pada saat proses dynamic analysis 
- Continue	= melanjutkan program sampai selesai atau sampai terkena breakpoint
- Step Into	= menjalankan instruksi berikutnya dan jika ada pemanggilan fungsi akan masuk 		kedalamnya
- Step Over	= Menjalankan instruksi namun jika ada pemanggilan fungsi dia akan melewatinya
