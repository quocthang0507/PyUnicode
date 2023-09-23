# https://github.com/vuthaihoc/py-unicode-convert

import re

patterns = {
	"TCVN3": [r'\w­[¬íêîëì]|®[¸µ¹¶·Ê¾»Æ¼½ÌÑÎÏªÕÒÖÓÔÝ×ÞØÜãßäáâ«èåéæç¬íêîëìóïôñòøõùö]', 0],
	"VNI_WIN": [r'[öô][ùøïûõ]|oa[ëùøïûõ]|ñ[aoeuôö][äàáåãùøïûõ]', re.IGNORECASE],
	"VIQR": [r'u[\+\*]o[\+\*]|dd[aoe][\(\^~\'`]|[aoe]\^[~`\'\.\?]|[uo]\+[`\'~\.\?]|a\([\'`~\.\?]', re.IGNORECASE],
	"UNICODE": [r'[Ạ-ỹ]', 0],
	"VISCII": [r'\wß[½¾¶þ·Þ]|ð[áàÕäã¤í¢£ÆÇè©ë¨êª«®¬­íì¸ïîóò÷öõô¯°µ±²½¾¶þ·ÞúùøüûÑ×ñØ]', 0],
	"VPS_WIN": [r'\wÜ[Ö§©®ª«]|Ç[áàåäãÃí¢¥£¤èËÈëêÍíìÎÌïóòÕõôÓÒ¶°Ö§©®ª«úùøûÛÙØ¿º]', 0],
	"VIETWARE_F": [r'\w§[¥ìéíêë]|¢[ÀªÁ¶ºÊÛÂÆÃÄÌÑÍÎ£ÕÒÖÓÔÛØÜÙÚâßãàá¤çäèåæ¥ìéíêëòîóïñ÷ôøõ]', 0],
	"VIETWARE_X": [r'[áãä][úöûøù]|à[õòûóô]|[åæ][ïìüíî]', re.IGNORECASE]
}


class Converter:
	"""Convert qua lai giua mot so bang ma cua Vietnam"""

	def __init__(self):
		"""Khoi tao"""
		self.TCVN3 = ["Aµ", "A¸", "¢", "A·", "EÌ", "EÐ", "£", "I×", "IÝ", "Oß",
					  "Oã", "¤", "Oâ", "Uï", "Uó", "Yý", "µ", "¸", "©", "·",
					  "Ì", "Ð", "ª", "×", "Ý", "ß", "ã", "«", "â", "ï",
					  "ó", "ý", "¡", "¨", "§", "®", "IÜ", "Ü", "Uò", "ò",
					  "¥", "¬", "¦", "­", "A¹", "¹", "A¶", "¶", "¢Ê", "Ê",
					  "¢Ç", "Ç", "¢È", "È", "¢É", "É", "¢Ë", "Ë", "¡¾", "¾",
					  "¡»", "»", "¡¼", "¼", "¡½", "½", "¡Æ", "Æ", "EÑ", "Ñ",
					  "EÎ", "Î", "EÏ", "Ï", "£Õ", "Õ", "£Ò", "Ò", "£Ó", "Ó",
					  "£Ô", "Ô", "£Ö", "Ö", "IØ", "Ø", "IÞ", "Þ", "Oä", "ä",
					  "Oá", "á", "¤è", "è", "¤å", "å", "¤æ", "æ", "¤ç", "ç",
					  "¤é", "é", "¥í", "í", "¥ê", "ê", "¥ë", "ë", "¥ì", "ì",
					  "¥î", "î", "Uô", "ô", "Uñ", "ñ", "¦ø", "ø", "¦õ", "õ",
					  "¦ö", "ö", "¦÷", "÷", "¦ù", "ù", "Yú", "ú", "Yþ", "þ",
					  "Yû", "û", "Yü", "ü", "."]

		self.UNICODE = ["À", "Á", "Â", "Ã", "È", "É", "Ê", "Ì", "Í", "Ò",
						"Ó", "Ô", "Õ", "Ù", "Ú", "Ý", "à", "á", "â", "ã",
						"è", "é", "ê", "ì", "í", "ò", "ó", "ô", "õ", "ù",
						"ú", "ý", "Ă", "ă", "Đ", "đ", "Ĩ", "ĩ", "Ũ", "ũ",
						"Ơ", "ơ", "Ư", "ư", "Ạ", "ạ", "Ả", "ả", "Ấ", "ấ",
						"Ầ", "ầ", "Ẩ", "ẩ", "Ẫ", "ẫ", "Ậ", "ậ", "Ắ", "ắ",
						"Ằ", "ằ", "Ẳ", "ẳ", "Ẵ", "ẵ", "Ặ", "ặ", "Ẹ", "ẹ",
						"Ẻ", "ẻ", "Ẽ", "ẽ", "Ế", "ế", "Ề", "ề", "Ể", "ể",
						"Ễ", "ễ", "Ệ", "ệ", "Ỉ", "ỉ", "Ị", "ị", "Ọ", "ọ",
						"Ỏ", "ỏ", "Ố", "ố", "Ồ", "ồ", "Ổ", "ổ", "Ỗ", "ỗ",
						"Ộ", "ộ", "Ớ", "ớ", "Ờ", "ờ", "Ở", "ở", "Ỡ", "ỡ",
						"Ợ", "ợ", "Ụ", "ụ", "Ủ", "ủ", "Ứ", "ứ", "Ừ", "ừ",
						"Ử", "ử", "Ữ", "ữ", "Ự", "ự", "Ỳ", "ỳ", "Ỵ", "ỵ",
						"Ỷ", "ỷ", "Ỹ", "ỹ", "."]

		self.VIQR = ["A`", "A'", "A^", "A~", "E`", "E'", "E^", "I`", "I'", "O`",
					 "O'", "O^", "O~", "U`", "U'", "Y'", "a`", "a'", "a^", "a~",
					 "e`", "e'", "e^", "i`", "i'", "o`", "o'", "o^", "o~", "u`",
					 "u'", "y'", "A(", "a(", "DD", "dd", "I~", "i~", "U~", "u~",
					 "O+", "o+", "U+", "u+", "A.", "a.", "A?", "a?", "A^'", "a^'",
					 "A^`", "a^`", "A^?", "a^?", "A^~", "a^~", "A^.", "a^.", "A('", "a('",
					 "A(`", "a(`", "A(?", "a(?", "A(~", "a(~", "A(.", "a(.", "E.", "e.",
					 "E?", "e?", "E~", "e~", "E^'", "e^'", "E^`", "e^`", "E^?", "e^?",
					 "E^~", "e^~", "E^.", "e^.", "I?", "i?", "I.", "i.", "O.", "o.",
					 "O?", "o?", "O^'", "o^'", "O^`", "o^`", "O^?", "o^?", "O^~", "o^~",
					 "O^.", "o^.", "O+'", "o+'", "O+`", "o+`", "O+?", "o+?", "O+~", "o+~",
					 "O+.", "o+.", "U.", "u.", "U?", "u?", "U+'", "u+'", "U+`", "u+`",
					 "U+?", "u+?", "U+~", "u+~", "U+.", "u+.", "Y`", "y`", "Y.", "y.",
					 "Y?", "y?", "Y~", "y~", "\\."]

		self.VNI_WIN = ["AØ", "AÙ", "AÂ", "AÕ", "EØ", "EÙ", "EÂ", "Ì", "Í", "OØ",
						"OÙ", "OÂ", "OÕ", "UØ", "UÙ", "YÙ", "aø", "aù", "aâ", "aõ",
						"eø", "eù", "eâ", "ì", "í", "oø", "où", "oâ", "oõ", "uø",
						"uù", "yù", "AÊ", "aê", "Ñ", "ñ", "Ó", "ó", "UÕ", "uõ",
						"Ô", "ô", "Ö", "ö", "AÏ", "aï", "AÛ", "aû", "AÁ", "aá",
						"AÀ", "aà", "AÅ", "aå", "AÃ", "aã", "AÄ", "aä", "AÉ", "aé",
						"AÈ", "aè", "AÚ", "aú", "AÜ", "aü", "AË", "aë", "EÏ", "eï",
						"EÛ", "eû", "EÕ", "eõ", "EÁ", "eá", "EÀ", "eà", "EÅ", "eå",
						"EÃ", "eã", "EÄ", "eä", "Æ", "æ", "Ò", "ò", "OÏ", "oï",
						"OÛ", "oû", "OÁ", "oá", "OÀ", "oà", "OÅ", "oå", "OÃ", "oã",
						"OÄ", "oä", "ÔÙ", "ôù", "ÔØ", "ôø", "ÔÛ", "ôû", "ÔÕ", "ôõ",
						"ÔÏ", "ôï", "UÏ", "uï", "UÛ", "uû", "ÖÙ", "öù", "ÖØ", "öø",
						"ÖÛ", "öû", "ÖÕ", "öõ", "ÖÏ", "öï", "YØ", "yø", "Î", "î",
						"YÛ", "yû", "YÕ", "yõ", "."]

		self.VISCII = ["À", "Á", "Â", "Ã", "È", "É", "Ê", "Ì", "Í", "Ò",
					   "Ó", "Ô", "õ", "Ù", "Ú", "Ý", "à", "á", "â", "ã",
					   "è", "é", "ê", "ì", "í", "ò", "ó", "ô", "õ", "ù",
					   "ú", "ý", "Å", "å", "Ð", "ð", "Î", "î", "", "û",
					   "´", "½", "¿", "ß", "€", "Õ", "Ä", "ä", "„", "¤",
					   "…", "¥", "†", "¦", "ç", "ç", "‡", "§", "", "í",
					   "‚", "¢", "Æ", "Æ", "Ç", "Ç", "ƒ", "£", "‰", "©",
					   "Ë", "ë", "ˆ", "¨", "Š", "ª", "‹", "«", "Œ", "¬",
					   "", "­", "Ž", "®", "›", "ï", "˜", "¸", "š", "÷",
					   "™", "ö", "", "¯", "", "°", "‘", "±", "’", "²",
					   "“", "µ", "•", "¾", "–", "¶", "—", "·", "³", "Þ",
					   "”", "þ", "ž", "ø", "œ", "ü", "º", "Ñ", "»", "×",
					   "¼", "Ø", "ÿ", "æ", "¹", "ñ", "Ÿ", "Ï", "Ü", "Ü",
					   "Ö", "Ö", "Û", "Û", "."]

		self.VPS_WIN = ["à", "Á", "Â", "‚", "×", "É", "Ê", "µ", "´", "¼",
						"¹", "Ô", "õ", "¨", "Ú", "Ý", "à", "á", "â", "ã",
						"è", "é", "ê", "ì", "í", "ò", "ó", "ô", "õ", "ù",
						"ú", "š", "ˆ", "æ", "ñ", "Ç", "¸", "ï", "¬", "Û",
						"÷", "Ö", "Ð", "Ü", "å", "å", "", "ä", "ƒ", "Ã",
						"„", "À", "…", "Ä", "Å", "Å", "Æ", "Æ", "", "í",
						"¢", "¢", "£", "£", "¤", "¤", "¥", "¥", "Ë", "Ë",
						"Þ", "È", "þ", "ë", "", "‰", "“", "Š", "”", "‹",
						"•", "Í", "Œ", "Œ", "·", "Ì", "Î", "Î", "†", "†",
						"½", "Õ", "–", "Ó", "—", "Ò", "˜", "°", "™", "‡",
						"¶", "¶", "", "§", "©", "©", "Ÿ", "ª", "¦", "«",
						"®", "®", "ø", "ø", "Ñ", "û", "­", "Ù", "¯", "Ø",
						"±", "º", "»", "»", "¿", "¿", "²", "ÿ", "œ", "œ",
						"›", "›", "Ï", "Ï", "."]

		self.VIETWARE_X = ["AÌ", "AÏ", "Á", "AÎ", "EÌ", "EÏ", "Ã", "Ç", "Ê", "OÌ",
						   "OÏ", "Ä", "OÎ", "UÌ", "UÏ", "YÏ", "aì", "aï", "á", "aî",
						   "eì", "eï", "ã", "ç", "ê", "oì", "oï", "ä", "oî", "uì",
						   "uï", "yï", "À", "à", "Â", "â", "É", "é", "UÎ", "uî",
						   "Å", "å", "Æ", "æ", "AÛ", "aû", "AÍ", "aí", "ÁÚ", "áú",
						   "ÁÖ", "áö", "ÁØ", "áø", "ÁÙ", "áù", "ÁÛ", "áû", "ÀÕ", "àõ",
						   "ÀÒ", "àò", "ÀÓ", "àó", "ÀÔ", "àô", "ÀÛ", "àû", "EÛ", "eû",
						   "EÍ", "eí", "EÎ", "eî", "ÃÚ", "ãú", "ÃÖ", "ãö", "ÃØ", "ãø",
						   "ÃÙ", "ãù", "ÃÛ", "ãû", "È", "è", "Ë", "ë", "OÜ", "oü",
						   "OÍ", "oí", "ÄÚ", "äú", "ÄÖ", "äö", "ÄØ", "äø", "ÄÙ", "äù",
						   "ÄÜ", "äü", "ÅÏ", "åï", "ÅÌ", "åì", "ÅÍ", "åí", "ÅÎ", "åî",
						   "ÅÜ", "åü", "UÛ", "uû", "UÍ", "uí", "ÆÏ", "æï", "ÆÌ", "æì",
						   "ÆÍ", "æí", "ÆÎ", "æî", "ÆÛ", "æû", "YÌ", "yì", "YÑ", "yñ",
						   "YÍ", "yí", "YÎ", "yî", "."]

		self.VIETWARE_F = ["", " ", "", "", "¬", "¯", "", "¸", "»", "¿",
						   "â", "", "á", "î", "ò", "ü", "ª", "À", "¡", "º",
						   "Ì", "Ï", "£", "Ø", "Û", "ß", "â", "¤", "á", "î",
						   "ò", "ü", "", "", "", "¢", "Ú", "Ú", "ñ", "ñ",
						   "", "¥", "", "§", "Á", "Á", "", "¶", "Ê", "Ê",
						   "Ç", "Ç", "¨", "È", "©", "É", "«", "Ë", "Å", "Å",
						   "Â", "Â", "Ã", "Ã", "Ä", "Ä", "¦", "Æ", "±", "Ñ",
						   "­", "Í", "®", "Î", "µ", "Õ", "²", "Ò", "³", "Ó",
						   "´", "Ô", "Ö", "Ö", "¹", "Ù", "¼", "Ü", "ã", "ã",
						   "à", "à", "ç", "ç", "ä", "ä", "å", "å", "æ", "æ",
						   "è", "è", "ì", "ì", "é", "é", "ê", "ê", "ë", "ë",
						   "í", "í", "ó", "ó", "ï", "ï", "×", "÷", "ô", "ô",
						   "õ", "õ", "ö", "ö", "ø", "ø", "ù", "ù", "ÿ", "ÿ",
						   "ú", "ú", "û", "û", "."]

		pass

	def convert(self, str_original, target_charset="UNICODE", source_charset=None):

		if (source_charset == None):
			source_charset = self.detectCharset(str_original)

		if (source_charset == None):
			raise TypeError("Can not get charset of str_original")

		source_charset = getattr(self, source_charset)
		target_charset = getattr(self, target_charset)

		map_length = len(source_charset)
		for number in range(map_length):
			str_original = str_original.replace(
				source_charset[number], "::" + str(number) + "::")

		for number in range(map_length):
			str_original = str_original.replace(
				"::" + str(number) + "::", target_charset[number])

		return str_original

	def detectCharset(self, str_input):
		for pattern in patterns:
			match = re.search(patterns[pattern][0],
							  str_input, patterns[pattern][1])
			if (match != None):
				return pattern
		return None
