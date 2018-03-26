#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>

class enc_key
{
public:
	enc_key() {};
	~enc_key() {};
	void add_key(char c) {
		if (std::none_of(v.begin(),v.end(),[&](char n) -> bool { return c == n; }))
			v.push_back(c);
	};
	void add_char_pair(char p,char q) {
		char_pairs.push_back(std::pair<char,char>(p,q));
	};
	int get_key_count() { return v.size(); };
	char get_nth_key(int n = 0) { return v[n]; };
	int get_char_pair_count() { return char_pairs.size(); };
	std::pair<char,char> get_nth_char_pair(int n) { return char_pairs[n]; };
private:
	std::vector<char> v;
	std::vector<std::pair<char,char> > char_pairs;
};

bool isValidChar(char *char_set,char c)
{
	if (char_set)
	{
		if (nullptr != strchr(char_set,c)) return true; else return false;
	}
	else
	{
		if (c > 0x7e) return false;
		else if (c < 0x20) return false;
		return true;
	}
}

void check_key(enc_key keys[],int n,char pass[],int pass_len,int &dropped,int &num_pass)
{
	for(int i = keys[n].get_char_pair_count() - 1;i >= 0;--i)
	{
		std::pair<char,char> char_pair = keys[n].get_nth_char_pair(i);
		pass[n] = char_pair.first;
		pass[15 - n] = char_pair.second;
		if (n == 0)
		{
			int zero_count = 0;
			int zero_idx = 0;
			for(int j = 0;j < 16;++j)
			{
				if (pass[j] == 0)
				{
					++zero_count;
					zero_idx = j;
				}
			}
			if (zero_count == 1)
			{
				int pass_length = 16 - zero_idx;
				bool f = true;
				if (pass_length == pass_len || pass_len == 0)
				{
					for(int j = pass_length;j < 16;++j)
					{
						if (j == (16 - pass_length)) continue;
						if (pass[j] != pass[j - pass_length])
						{
							f = false;
							break;
						}
					}
					if (f)
					{
						std::cout << "pass found:";
						for(int j = 0;j < 16;++j)
						{
							if (pass[j])
								std::cout << " " << (char)pass[j];
							else
								std::cout << " " << "(NULL)";
						}
						std::cout << " , len = " << std::dec << pass_length << std::endl;
						++num_pass;
					}
					else
					{
						++dropped;
					}
				}
				else
				{
					++dropped;
				}
			}
			else
			{
				++dropped;
			}
		}
		else
		{
			check_key(keys,n - 1,pass,pass_len,dropped,num_pass);
		}
	}
}


void search_key(char h[],char *char_set,int pass_len)
{
	enc_key keys[8];
	char pass[16];
	int dropped = 0;
	int num_pass = 0;
	unsigned long long total_keys = 1;
	for(int k = 15;k >= 8;--k)
	{
		for(int p = 0;p < 128;++p)
		{
			if (!isValidChar(char_set,p)) continue;
			for(int q = 0;q < 128;++q)
			{
				if (!isValidChar(char_set,q)) continue;
				int x = (p * (15 - k)) + ((q << 4) & 0xff);
				int y = (q * k) + ((p << 4) & 0xff);
				x &= 0xff;
				y &= 0xff;
				int r = p * (15 - k);
				int s = q * k;
				r &= 0xff;
				s &= 0xff;
				if (((r ^ s) & 0x0f) != (((int)h[k]) & 0x0f))
					continue;
				if ((x ^ y) == (((int)h[k]) & 0xff))
				{
					std::cout << "found key pair: " << x << " , " << y << std::endl;
					std::cout << "(p = " << (char)p << " , q = " << (char)q << ")" << std::endl;
					keys[15 - k].add_key(x);
					keys[15 - k].add_char_pair(p,q);
				}
			}
		}
	}
	for(int i = 0;i < 8;++i)
	{
		std::cout << "key count for h = " << std::hex << (int)h[15 - i] << ": " << std::dec << keys[i].get_key_count() << std::endl;
		total_keys *= keys[i].get_key_count();
	}
	std::cout << "possible encryption keys are successfully recovered." << std::endl;
	std::cout << "now check them" << std::endl;
	check_key(keys,7,pass,pass_len,dropped,num_pass);
	std::cout << std::dec << total_keys << " keys in total" << std::endl;
	std::cout << std::dec << num_pass << " passwords are found" << std::endl;
	std::cout << std::dec << dropped << " pass are dropped" << std::endl;
}

int main(int argc,char *argv[])
{
	if (argc >= 2)
	{
		char const sig[4] {0x07,0x11,0x12,0x07};
		char       hdr[4] {};
		char const a[4] {0x30,0x30,0xff,0xfe};
		char       b[4] {};
		char h[16] = {0}; // assumes char is signed.
		std::fstream file(argv[1],std::ios_base::in | std::ios_base::binary);
		file.read(hdr,4);
		if (memcmp(hdr,sig,4) == 0)
		{
			int c;
			int key_len = 0;
			while (EOF != (c = file.get()) && key_len < 16)
			{
				h[key_len++] = c & 0xff;
			}
			if (key_len != 16)
			{
				std::cout << "key length is too short" << std::endl;
				return -1;
			}
			b[0] = c;
			file.read(&b[1],3);
			if (memcmp(b,a,4) == 0)
			{
				int pass_len = 0;
				char *char_set = nullptr;
				std::cout << "searching key for h=";
				for(auto &k : h) { std::cout << " " << std::hex << (int)(k & 0xff); };
				std::cout << std::endl;
				for(int i = 2;i < argc && i < 4;++i)
				{
					if (strnicmp(argv[i],"--char_set=",11) == 0)
					{
						char_set = argv[i] + 11;
					}
					else if (strnicmp(argv[i],"--pass_len=",11) == 0)
					{
						pass_len = atoi(argv[i] + 11);
					}
				}
				search_key(h,char_set,pass_len);
			}
			else
			{
				std::cout << "this file is not cat memo note text" << std::endl;
			}
		}
		else
		{
			std::cout << "signature mismatch" << std::endl;
		}
	}
	else
	{
		std::cout << "Usage: " << argv[0] << " file [option]" << std::endl;
		std::cout << "option:" << std::endl;
		std::cout << "--charset=[char set] : used char set" << std::endl;
		std::cout << "--pass_len=[digit] : password length to search" << std::endl;
		std::cout << "example: " << argv[0] << " [file] --char_set=ABCDEFGHIJKLMNOPQRSTUVWXYZ --pass_len=8" << std::endl;
		std::cout << "example: " << argv[0] << " [file] --char_set=0123456789abcdef --pass_len=0" << std::endl;
		std::cout << "**--pass_len=0 means no restriction (search for all password)" << std::endl;
	}
	return 0;
}
