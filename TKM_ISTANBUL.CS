using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Linq;
using System.Threading;
using System.IO;
using System.Globalization;
   

namespace Trafik_istanbul
{
    public class TKMDecrypt
    {
        static int[] refTable1 = new int[] { 237, 220, 239, 100, 120, 248, 241, 54, 244, 169, 178, 230, 68, 203, 43, 127, 175, 114, 154, 60, 218, 20, 140, 238, 84, 95, 93, 142, 62, 3, 69, 255, 156, 152, 211, 148, 112, 245, 246, 113, 161, 99, 123, 59, 94, 21, 209, 19, 205, 122, 2, 91, 72, 184, 240, 82, 131, 213, 201, 90, 31, 181, 227, 221, 222, 162, 104, 200, 217, 133, 149, 190, 81, 85, 53, 6, 197, 103, 44, 102, 79, 96, 186, 219, 27, 229, 139, 76, 145, 89, 83, 247, 34, 193, 58, 61, 48, 174, 35, 250, 46, 182, 143, 232, 71, 136, 18, 50, 78, 128, 39, 108, 109, 75, 42, 126, 233, 51, 115, 74, 47, 101, 49, 32, 16, 172, 88, 151, 111, 45, 116, 55, 188, 118, 234, 22, 77, 228, 67, 36, 198, 15, 226, 242, 28, 153, 121, 33, 12, 163, 129, 107, 135, 98, 70, 150, 63, 144, 124, 158, 11, 171, 86, 159, 66, 231, 141, 64, 56, 160, 7, 8, 155, 206, 5, 23, 1, 37, 9, 40, 110, 29, 132, 195, 216, 105, 10, 225, 125, 24, 176, 65, 130, 253, 235, 192, 87, 189, 41, 14, 249, 30, 166, 243, 164, 80, 194, 183, 167, 173, 26, 180, 202, 73, 191, 97, 57, 210, 146, 236, 207, 147, 177, 215, 223, 170, 25, 214, 38, 252, 137, 254, 52, 208, 196, 0, 4, 13, 138, 212, 117, 165, 179, 106, 119, 224, 134, 168, 199, 204, 17, 157, 251, 187, 185, 92 };
        static int[] refTable2 = new int[] { 235, 176, 50, 29, 236, 174, 75, 170, 171, 178, 186, 160, 148, 237, 199, 141, 124, 250, 106, 47, 21, 45, 135, 175, 189, 226, 210, 84, 144, 181, 201, 60, 123, 147, 92, 98, 139, 177, 228, 110, 179, 198, 114, 14, 78, 129, 100, 120, 96, 122, 107, 117, 232, 74, 7, 131, 168, 216, 94, 43, 19, 95, 28, 156, 167, 191, 164, 138, 12, 30, 154, 104, 52, 213, 119, 113, 87, 136, 108, 80, 205, 72, 55, 90, 24, 73, 162, 196, 126, 89, 59, 51, 255, 26, 44, 25, 81, 215, 153, 41, 3, 121, 79, 77, 66, 185, 243, 151, 111, 112, 180, 128, 36, 39, 17, 118, 130, 240, 133, 244, 4, 146, 49, 42, 158, 188, 115, 15, 109, 150, 192, 56, 182, 69, 246, 152, 105, 230, 238, 86, 22, 166, 27, 102, 157, 88, 218, 221, 35, 70, 155, 127, 33, 145, 18, 172, 32, 251, 159, 163, 169, 40, 65, 149, 204, 241, 202, 208, 247, 9, 225, 161, 125, 209, 97, 16, 190, 222, 10, 242, 211, 61, 101, 207, 53, 254, 82, 253, 132, 197, 71, 214, 195, 93, 206, 183, 234, 76, 140, 248, 67, 58, 212, 13, 249, 48, 173, 220, 233, 46, 217, 34, 239, 57, 227, 223, 184, 68, 20, 83, 1, 63, 64, 224, 245, 187, 142, 62, 137, 85, 11, 165, 103, 116, 134, 194, 219, 0, 23, 2, 54, 6, 143, 203, 8, 37, 38, 91, 5, 200, 99, 252, 229, 193, 231, 31 };

        static int KEY_SIZE = 8;
        static int CLEAR_TEXT_LENGTH_SECTION_LENGTH = 7;
        static int KEY_SECTION_LENGTH = 30;
        // static int RANDOM_STRING_LEN = 62;

        static string INT_TO_CHAR_TABLE = (char)(0) + "ZNÇV bCKıUt01ÜLşEaB23OÖ456u7M8S!9ŞFRDAIPHpTĞiü/J+%hrGYsyc&" + "(zn)çvjd=ekğmog?*-öf_İ{l}[]#$@<>;.:\"\'WwQqXx\\\n\r,|~é^" +
           (char)(1) + (char)(2) + (char)(3) + (char)(4) + (char)(5) + (char)(6) + (char)(7) + (char)(8) +
           (char)(9) + (char)(11) + (char)(12) + (char)(14) + (char)(15) + (char)(16) + (char)(17) + (char)(18) + (char)(19) + (char)(20);

        static string HexChars = "0123456789ABCDEF";

        public static string Decrypt0(string cipherText, string key)
        {
            var _loc7_ = 0;
            var _loc14_ = 0;
            var _loc15_ = string.Empty;
            var _loc16_ = 0;
            var _loc17_ = 0;
            var _loc18_ = 0;
            var _loc19_ = 0;
            var _loc20_ = 0;
            var _loc21_ = 0;
            var _loc22_ = 0;
            var _loc3_ = "";
            var _loc4_ = "";
            var _loc5_ = "";
            var _loc6_ = "";
            var _loc8_ = cipherText[(cipherText.Length - 1)] - (char)'0';
            switch (_loc8_)
            {
                case 0:
                    _loc6_ = cipherText;
                    break;
                case 1:
                    _loc6_ = convertFromHexStr(cipherText, -1);
                    break;
                case 2:
                    _loc14_ = cipherText[(cipherText.Length - 2)] - (char)'0';
                    _loc15_ = deShuffleHexStr(cipherText, key, _loc14_, -2);
                    _loc6_ = convertFromHexStr(_loc15_, 0);
                    break;
            }
            var _loc9_ = new int[(KEY_SIZE)];
            _loc7_ = 0;
            while (_loc7_ < KEY_SIZE)
            {
                _loc16_ = (char)_loc6_[(20 + _loc7_)] - 90;
                _loc17_ = (int)(_loc6_[25 + KEY_SIZE + _loc16_] - 90);
                _loc9_[_loc7_] = _loc17_;
                _loc7_++;
            }
            var _loc10_ = 0;
            _loc7_ = 0;
            while (_loc7_ < KEY_SIZE)
            {
                _loc10_ = _loc10_ + _loc9_[_loc7_];
                _loc7_++;
            }
            _loc10_ = _loc10_ % _loc9_[0];
            _loc10_++;
            var _loc11_ = 0;
            _loc7_ = 0;
            while (_loc7_ < 5)
            {
                _loc18_ = _loc6_[(20 + KEY_SIZE + _loc7_)] - (60 + _loc7_);
                _loc5_ = _loc5_ + (char)(_loc18_);
                _loc7_++;
            }
            _loc11_ = Convert.ToInt32(_loc5_);
            _loc4_ = _loc6_.Substring(55 + KEY_SIZE, _loc11_);
            var _loc12_ = _loc11_;
            var _loc13_ = 0;
            _loc7_ = 0;
            while (_loc7_ < _loc12_)
            {
                _loc19_ = (int)(_loc4_[(_loc7_)]);
                _loc20_ = _loc9_[_loc13_ % KEY_SIZE];
                _loc21_ = _loc19_ << 8 - _loc20_ & 255;
                _loc19_ = (_loc19_ >> _loc20_ | _loc21_) & 255;
                _loc22_ = _loc19_;
                _loc22_ = _loc22_ - (int)(_loc10_);
                _loc3_ = _loc3_ + INT_TO_CHAR_TABLE[(_loc22_)];
                _loc13_++;
                _loc7_++;
            }
            return _loc3_;
        }

        /// <summary>
        /// TKMDecryptV12
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string Decrypt1(string cipherText, string key)
        {
            var _loc7_ = 0;
            var _loc14_ = 0;
            var _loc15_ = string.Empty;
            var _loc16_ = 0;
            var _loc17_ = 0;
            var _loc18_ = 0;
            var _loc19_ = 0;
            var _loc20_ = 0;
            var _loc21_ = 0;
            var _loc22_ = 0;
            var _loc3_ = "";
            var _loc4_ = "";
            var _loc5_ = "";
            var _loc6_ = "";
            var _loc8_ = cipherText[(cipherText.Length - 1)] - (char)'0';
            switch (_loc8_)
            {
                case 0:
                    _loc6_ = cipherText;
                    break;
                case 1:
                    _loc6_ = convertFromHexStr(cipherText, -1);
                    break;
                case 2:
                    _loc14_ = cipherText[(cipherText.Length - 2)] - (char)'0';
                    _loc15_ = deShuffleHexStr(cipherText, key, _loc14_, -2);
                    _loc6_ = convertFromHexStr(_loc15_, 0);
                    break;
            }
            var _loc9_ = new int[(KEY_SIZE)];
            _loc7_ = 0;
            while (_loc7_ < KEY_SIZE)
            {
                _loc16_ = (char)_loc6_[(20 + _loc7_)] - 90;
                _loc17_ = (int)(_loc6_[20 + CLEAR_TEXT_LENGTH_SECTION_LENGTH + KEY_SIZE + _loc16_] - 90);
                _loc9_[_loc7_] = _loc17_;
                _loc7_++;
            }
            var _loc10_ = 0;
            _loc7_ = 0;
            while (_loc7_ < KEY_SIZE)
            {
                _loc10_ = _loc10_ + _loc9_[_loc7_];
                _loc7_++;
            }
            _loc10_ = _loc10_ % _loc9_[0];
            _loc10_++;
           var _loc11_ = 0;
            _loc7_ = 0;
            while (_loc7_ < CLEAR_TEXT_LENGTH_SECTION_LENGTH)
            {
                _loc18_ = _loc6_[(20 + KEY_SIZE + _loc7_)] - (60 + _loc7_);
                _loc5_ = _loc5_ + (char)(_loc18_);
               _loc7_++;
            }
            _loc11_ = Convert.ToInt32(_loc5_);
            _loc4_ = _loc6_.Substring(20 + KEY_SECTION_LENGTH + CLEAR_TEXT_LENGTH_SECTION_LENGTH + KEY_SIZE);
            var _loc12_ = _loc11_;
            var _loc13_ = 0;
            _loc7_ = 0;
            while (_loc7_ < _loc12_)
            {
                _loc19_ = (int)(_loc4_[(_loc7_)]);
                _loc20_ = _loc9_[_loc13_ % KEY_SIZE];
                _loc21_ = _loc19_ << 8 - _loc20_ & 255;
                _loc19_ = (_loc19_ >> _loc20_ | _loc21_) & 255;
                _loc22_ = _loc19_;
                _loc22_ = _loc22_ - (int)(_loc10_);
                _loc3_ = _loc3_ + INT_TO_CHAR_TABLE[(_loc22_)];
                _loc13_++;
                _loc7_++;
            }
            return _loc3_;
        }

        public static string Decrypt2(string cipherText)
        {
            byte[] inBytes = ASCIIEncoding.UTF8.GetBytes(cipherText);
            byte[] outBytes = new byte[inBytes.Length];

            int key = 3;
            int c1 = 6;
            int c2 = 3; //loc6
            while (c1 < inBytes.Length)
            {
                int i1 = (inBytes[c1++] - 48);
                int i2 = (inBytes[c1++] - 48);

                if (i1 > 9) i1 -= 7;
                if (i2 > 9) i2 -= 7;

                i1 = (i1 << 4) + i2;
                i1 = i1 ^ refTable1[key + (c2 & 15)];
                i1 = refTable2[i1];
                outBytes[c2 - 3] = (byte)i1;
                c2++;
            }

            string clearText = ASCIIEncoding.UTF8.GetString(outBytes);
            return clearText.Substring(0, clearText.IndexOf('\0'));
        }

        protected static string convertFromHexStr(string param1, int param2)
        {
            int _loc6_ = 0;
            int _loc3_ = param1.Length + param2;
            var _loc4_ = string.Empty;
            var _loc5_ = 0;
            while (_loc5_ < _loc3_)
            {
                _loc6_ = (int)(HexChars.IndexOf(param1[_loc5_]) << 4 | HexChars.IndexOf(param1[_loc5_ + 1]));
                _loc4_ = _loc4_ + (char)(_loc6_);
                _loc5_ = _loc5_ + 2;
            }
            return _loc4_;
        }

        protected static string deShuffleHexStr(string param1, string param2, int param3, int param4)
        {
            var _loc5_ = 0;
            var _loc6_ = 0;
            var _loc12_ = 0;
            var _loc13_ = 0;
            var _loc14_ = 0;
            var _loc7_ = new int[(KEY_SIZE)];
            var _loc8_ = new List<int>();
            _loc5_ = 0;
            while (_loc5_ < KEY_SIZE)
            {
                _loc7_[(_loc5_ + param3) % KEY_SIZE] = (char)param2[(_loc5_)] - (char)'0';
                _loc5_++;
            }
            var _loc9_ = param1.Length + param4;
            var _loc10_ = param1.Substring(0, _loc9_);
            int _loc11_ = _loc9_ / KEY_SIZE;
            var _loc15_ = 0;
            while (_loc15_ < _loc10_.Length)
            {
                _loc8_.Add((char)_loc10_[_loc15_]);
                _loc15_++;
            }
            _loc5_ = 0;
            while (_loc5_ < _loc11_)
            {
                _loc12_ = _loc5_ * KEY_SIZE;
                _loc6_ = 0;
                while (_loc6_ < KEY_SIZE)
                {
                    _loc13_ = _loc12_ + _loc7_[_loc6_];
                    _loc14_ = (char)param1[(_loc12_ + _loc6_)];
                    //  _loc8_.splice(_loc13_,1,_loc14_);
                    _loc8_[_loc13_] = _loc14_;
                    _loc6_++;
                }
                _loc5_++;
            }
            _loc10_ = "";
            _loc5_ = 0;
            while (_loc5_ < _loc8_.Count)
            {
                _loc10_ = _loc10_ + (char)(_loc8_[_loc5_]);
                _loc5_++;
            }
            return _loc10_;
        }
    }
	
	  class Coords
    {
        string _Segment; Int32 _uid; double _lon, _lat;

        public string Segment { get { return _Segment; } set { _Segment = value; } }
        public Int32 uID { get { return _uid; } set { _uid = value; } }
        public double Lon { get { return _lon; } set { _lon = value; } }
        public double Lat { get { return _lat; } set { _lat = value; } }
    }


    class Program
    {
        static void Main(string[] args)
        {
			
			string t_i =DownloadTrafficIndex();
			
			Console.WriteLine("genel yogunluk " +t_i);
			
			
            koordinatlar();
           // Console.WriteLine(mesafe("472"));
            yollar();


			System.Threading.Thread.Sleep(-1);
			Console.Read();

            Console.ReadLine();
        }
		
		        public static List<Coords> ids = new List<Coords> {/*new Coords {   Segment = 472, uID = 0, Lon = 42.22 , Lat=29.55}*/ };
        public static void koordinatlar()
        {
            string allkoor = "";
            // koordinatlar
            using (WebClient wc = new WebClient())
            {
             //   string encData = wc.DownloadString("https://uym.ibb.gov.tr/YHarita/res/r0.txt");
               
               
 // yoksa kontrol et, varsa da süreye göre güncelle yapılabilir 
 string encData = wc.DownloadString(@"...\tkm_r0.txt");
			   var res = TKMDecrypt.Decrypt2(encData);
                allkoor = res;
            }

            string[] wl = allkoor.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            //471; 4; 29.0551587; 41.0909433; 471; 202; 2; 4; 0; 10; SARIYER;
            foreach (string d in wl)
            {
                string[] lst = d.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

                ids.Add(new Coords
                {
                    Segment = lst[0],
                    uID = int.Parse(lst[1]),
                    Lon = double.Parse(lst[2], CultureInfo.InvariantCulture),
                    Lat = double.Parse(lst[3], CultureInfo.InvariantCulture)
                });
            }

            // var query = from p in ids where p.uID > 0 select p.Segment;

        }

        public static double mesafe(string segm)
        {

            double lon1 = 0, lon2 = 0, lat1 = 0, lat2 = 0;
            var uquery = from p in ids where p.Segment == segm select p.uID;

            int mx = uquery.Max();

            foreach (Coords liste in ids)
            {
                if (liste.Segment == segm && liste.uID == 0) { lon1 = liste.Lon; lat1 = liste.Lat; }
                if (liste.Segment == segm && liste.uID == mx) { lon2 = liste.Lon; lat2 = liste.Lat; }

            }

            double km = Haversine.calculate(lat1, lon1, lat2, lon2) +0.015;

            return km;
        }
        public static class Haversine
        {
            public static double calculate(double lat1, double lon1, double lat2, double lon2)
            {
                var R = 6372.8; // In kilometers
                var dLat = toRadians(lat2 - lat1);
                var dLon = toRadians(lon2 - lon1);
                lat1 = toRadians(lat1);
                lat2 = toRadians(lat2);

                var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) + Math.Sin(dLon / 2) * Math.Sin(dLon / 2) * Math.Cos(lat1) * Math.Cos(lat2);
                var c = 2 * Math.Asin(Math.Sqrt(a));
                return R * 2 * Math.Asin(Math.Sqrt(a));
            }

            public static double toRadians(double angle)
            {
                return Math.PI * angle / 180.0;
            }
        }


        public static double zaman_sn(double yol, double hiz)
        {
			// YOL = HIZ X ZAMAN
			double zaman;
			
		   try{
			   zaman = yol / (double)hiz*3600;
			   
			   
		   } 
		   catch  {
		  zaman =-1000000000;
		  }
		
			return zaman;
		}


   public static void yollar()
        {
            string[] kopru_sonrasi = { "1748", "7529", "7530", "1749", "475", "7531", "476", "477", "7532", "478", "7533", "479", "480", "7534", "7535", "481", "482", "7536", "7537", "483", "484", "7538", "485", "7539", "7540", "486", "487", "7541", "488", "7542", "314", "315", "316","317" };
            string[] statdan = { "72", "1790", "1791", "1792", "467", "468", "469", "470", "471", "472" };
            string[] leventten = { "72", "1790", "73", "74", "58", "59", "469", "470", "471", "472" };
  
            string tkm;
            tkm = DownloadTrafficData();
           // Console.WriteLine(ix);
            Console.WriteLine("...........DownloadTrafficData..............");

            string[] w = tkm.Split(new[] {'&'}, StringSplitOptions.RemoveEmptyEntries);

            int toplam_ygnluk,toplam_hiz,adet;
            double toplam_km,toplam_sure,stad_sn,levent_sn, kopru_sn,stad_km,levent_km, kopru_km,toplam_p_hiz;
			stad_sn=0;
			levent_sn=0; 
			kopru_sn=0;
			stad_km=0;
			levent_km=0; 
			kopru_km=0;
			   try{
            Console.WriteLine("...........stadtan..............");
            toplam_ygnluk = 0;
            toplam_hiz = 0;
            toplam_p_hiz = 0;
            toplam_sure = 0;
            toplam_km = 0;
            adet = 0;
			/*
28.6610959275597
28.6610959275597 stadtan km yol 63.3153060616108 dakika 7.54454115188466 ort m/sn
29.055515047142
29.055515047142 leventten km yol 62.885153370605 dakika 7.7006822463344 ort m/sn
           */
		   foreach (string d in w)
            {
                string[] lst = d.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                 
                if (statdan.Any(x => x == lst[0]))
                {
				double kms = mesafe(lst[0].ToString());
				toplam_km= toplam_km + kms;
				int hiz = int.Parse(lst[1].ToString());
				double payli_hiz = (double)hiz*0.85;
				toplam_p_hiz = toplam_p_hiz+ payli_hiz;
				double zaman= zaman_sn(kms,payli_hiz);
				int ygnluk = int.Parse(lst[2].ToString());
				toplam_ygnluk =toplam_ygnluk+ ygnluk;
				toplam_hiz = toplam_hiz + hiz;
				toplam_sure = toplam_sure + zaman;
            
				adet++;  
                 Console.WriteLine(d+" | "+kms.ToString()+" km | "+(zaman/60).ToString()+" seg/dk "); 
                }
             }
			Console.WriteLine("segment:"+ adet.ToString()); 
			Console.WriteLine("km:"+ toplam_km.ToString());
			Console.WriteLine("toplam_ygnluk:"+ toplam_ygnluk.ToString()); 
			Console.WriteLine("ortalama_ygnluk:"+ (toplam_ygnluk/adet).ToString()); 
			Console.WriteLine("toplam_hiz:"+ toplam_hiz.ToString()); 
			Console.WriteLine("toplam_p_hiz:"+ toplam_p_hiz.ToString()); 
			Console.WriteLine("toplam_sure(mn):"+ (toplam_sure/60).ToString()); 

			stad_sn =toplam_sure;
			stad_km =toplam_km;

			Console.WriteLine("...........bitti stadtan..............");
			   }catch (Exception ex){
			Console.WriteLine(ex.ToString());
					}
		   try{
            Console.WriteLine("...........leventten..............");  
            toplam_ygnluk = 0;
            toplam_hiz = 0;
			toplam_p_hiz =0;
            toplam_sure = 0;
			adet=0;
			toplam_km=0;

			foreach (string d in w)
            {
                string[] lst = d.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries);

                if (leventten.Any(x => x == lst[0]))
                {	
				double kms = mesafe(lst[0].ToString());
				toplam_km= toplam_km + kms;
				int hiz = int.Parse(lst[1].ToString());
				double payli_hiz = (double)hiz*0.85;
				toplam_p_hiz = toplam_p_hiz+ payli_hiz;
				double zaman= zaman_sn(kms,payli_hiz);
				toplam_sure = toplam_sure + zaman;
				int ygnluk = int.Parse(lst[2].ToString());
				toplam_ygnluk =toplam_ygnluk+ ygnluk;
				toplam_hiz = toplam_hiz + hiz;	
				adet++;
                   Console.WriteLine(d+" | "+kms.ToString()+" km | "+(zaman/60).ToString()+" seg/dk "); 
               }

            }   			       
			Console.WriteLine("segment:"+ adet.ToString()); 
			Console.WriteLine("km:"+ toplam_km.ToString());
			Console.WriteLine("toplam_ygnluk:"+ toplam_ygnluk.ToString()); 
			Console.WriteLine("ortalama_ygnluk:"+ (toplam_ygnluk/adet).ToString()); 
			Console.WriteLine("toplam_hiz:"+ toplam_hiz.ToString()); 
			Console.WriteLine("toplam_p_hiz:"+ toplam_p_hiz.ToString()); 
			Console.WriteLine("toplam_sure(mn):"+ (toplam_sure/60).ToString()); 
			levent_sn =toplam_sure;
			levent_km =toplam_km;
			Console.WriteLine("...........bitti leventten..............");  
		   }catch (Exception ex){
			Console.WriteLine(ex.ToString());
					}

		   try{
			Console.WriteLine("...........kopru sonrasi..............");
			toplam_ygnluk = 0;
			toplam_hiz = 0;
			toplam_p_hiz =0;
			toplam_sure = 0;
			adet=0;
			toplam_km=0;

			foreach (string d in w)
            {
                string[] lst = d.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries);

                if (kopru_sonrasi.Any(x => x == lst[0]))
                {	
				double kms = mesafe(lst[0].ToString());
				toplam_km= toplam_km + kms;
				int hiz = int.Parse(lst[1].ToString());
				double payli_hiz = (double)hiz*0.85;
				toplam_p_hiz = toplam_p_hiz+ payli_hiz;
				double zaman= zaman_sn(kms,payli_hiz);
				toplam_sure = toplam_sure + zaman;
				int ygnluk = int.Parse(lst[2].ToString());
				toplam_ygnluk =toplam_ygnluk+ ygnluk;
				toplam_hiz = toplam_hiz + hiz;
				adet++;
                  Console.WriteLine(d+" | "+kms.ToString()+" km | "+(zaman/60).ToString()+" seg/dk "); 
               }

            }  
			Console.WriteLine("segment:"+ adet.ToString()); 
			Console.WriteLine("km:"+ toplam_km.ToString()); 
			Console.WriteLine("toplam_ygnluk:"+ toplam_ygnluk.ToString()); 
			Console.WriteLine("ortalama_ygnluk:"+ (toplam_ygnluk/adet).ToString()); 
			Console.WriteLine("toplam_hiz:"+ toplam_hiz.ToString()); 
			Console.WriteLine("toplam_p_hiz:"+ toplam_p_hiz.ToString()); 
			Console.WriteLine("toplam_sure(mn):"+ (toplam_sure/60).ToString()); 
			kopru_sn =toplam_sure; 
			kopru_km =toplam_km;
			Console.WriteLine("...........bitti kopru sonrasi..............");
     		   }catch (Exception ex){
			Console.WriteLine(ex.ToString());
					}
			var dateAndTime_Glb = DateTime.Now.ToString();

			Console.WriteLine(dateAndTime_Glb);
			Console.WriteLine("...............................................");
 
		Console.WriteLine("28.6610959275597");
		Console.WriteLine( (stad_km+kopru_km).ToString() +" stadtan km yol "+ ((stad_sn+kopru_sn)/60).ToString() +" dakika " +(((stad_km+kopru_km)*1000/(stad_sn+kopru_sn))).ToString()+" ort m/sn") ; 

		Console.WriteLine("29.055515047142");
		Console.WriteLine((levent_km+kopru_km).ToString() +" leventten km yol "+ ((kopru_sn+levent_sn)/60).ToString() +" dakika "+(((levent_km+kopru_km)*1000/(levent_sn+kopru_sn))).ToString()+" ort m/sn"); 

			
					}

        public static string DownloadTrafficIndex()
        {
            // trafic index value
            using (WebClient wc = new WebClient())
            {
                string encData = wc.DownloadString("https://tkmservices.ibb.gov.tr/data/IntensityMap/TrafficIndex.aspx?t=1576523863772");
                string trafficIndexStr = TKMDecrypt.Decrypt0(encData, "60413275");
                return trafficIndexStr;
            }
        } 

        public static string DownloadTrafficData()
        {
            // speed sensors
            using (WebClient wc = new WebClient())
            {
                string encData = wc.DownloadString("https://tkmservices.ibb.gov.tr/data/IntensityMap/TrafficDataNew.aspx?t=1576523984269");
                string speedDataStr = TKMDecrypt.Decrypt0(encData, "62403715");
                return speedDataStr;
            }
        }

        public static string DownloadParkingData()
        {
            // parking data
            using (WebClient wc = new WebClient())
            {
                string encData = wc.DownloadString("https://tkmservices.ibb.gov.tr/data/IntensityMap/ParkingLotData.aspx");
                string parkingDataStr = TKMDecrypt.Decrypt0(encData, "74205136");
                return parkingDataStr;
            }
        }

        public static string DownloadAnnouncements()
        {
            // announcement data
            using (WebClient wc = new WebClient())
            {
                string encData = wc.DownloadString("https://tkmservices.ibb.gov.tr/data/IntensityMap/AnnouncementData.aspx");
                string announceDataStr = TKMDecrypt.Decrypt0(encData, "50614732").Replace('\r', ' ').Replace('\n', ' '); // replace new lines
                return announceDataStr;
            }
        }

        public static string DownloadWeatherData()
        {
            // weather data
            using (WebClient wc = new WebClient())
            {
                string encData = wc.DownloadString("https://tkmservices.ibb.gov.tr/data/IntensityMap/WeatherData.aspx");
                string weatherDataStr = TKMDecrypt.Decrypt0(encData, "26107354");
                return weatherDataStr;
            }
        }

        public static void DownloadStaticFiles(string saveDir)
        {
            string staticBase = "https://uym.ibb.gov.tr/YHarita/res/";

            for (int i = 1; i <= 8; i++)
            {
                string address = String.Format("{0}d{1:00}.txt", staticBase, i);
                Console.WriteLine(address);
                using (WebClient wc = new WebClient())
                {
                    var encResult = wc.DownloadString(address);
                    var res = TKMDecrypt.Decrypt2(encResult);
                    File.WriteAllText(Path.Combine(saveDir, String.Format("d{0:00}.txt", i)), res);
                    wc.Dispose();
                }
            }

            for (int i = 0; i <= 4; i++)
            {
                string address = String.Format("{0}r{1}.txt", staticBase, i);
                Console.WriteLine(address);
                using (WebClient wc = new WebClient())
                {
                    var encResult = wc.DownloadString(address);
                    var res = TKMDecrypt.Decrypt2(encResult);
                    File.WriteAllText(Path.Combine(saveDir, String.Format("r{0}.txt", i)), res);
                    wc.Dispose();
                }
            }
        }
    }
}
