import os
import re

patterns = {
	"TCVN3"        : [ r'\w­[¬íêîëì]|®[¸µ¹¶·Ê¾»Æ¼½ÌÑÎÏªÕÒÖÓÔÝ×ÞØÜãßäáâ«èåéæç¬íêîëìóïôñòøõùö]', 0],
	"VNI_WIN"      : [r'[öô][ùøïûõ]|oa[ëùøïûõ]|ñ[aoeuôö][äàáåãùøïûõ]', re.IGNORECASE],
	"VIQR"         : [r'u[\+\*]o[\+\*]|dd[aoe][\(\^~\'`]|[aoe]\^[~`\'\.\?]|[uo]\+[`\'~\.\?]|a\([\'`~\.\?]', re.IGNORECASE],
	"UNICODE"      : [r'[Ạ-ỹ]', 0],
	"VISCII"       : [r'\wß[½¾¶þ·Þ]|ð[áàÕäã¤í¢£ÆÇè©ë¨êª«®¬­íì¸ïîóò÷öõô¯°µ±²½¾¶þ·ÞúùøüûÑ×ñØ]', 0],
	"VPS_WIN"      : [r'\wÜ[Ö§©®ª«]|Ç[áàåäãÃí¢¥£¤èËÈëêÍíìÎÌïóòÕõôÓÒ¶°Ö§©®ª«úùøûÛÙØ¿º]', 0],
	"VIETWARE_F"   : [r'\w§[¥ìéíêë]|¢[ÀªÁ¶ºÊÛÂÆÃÄÌÑÍÎ£ÕÒÖÓÔÛØÜÙÚâßãàá¤çäèåæ¥ìéíêëòîóïñ÷ôøõ]', 0],
	"VIETWARE_X"   : [r'[áãä][úöûøù]|à[õòûóô]|[åæ][ïìüíî]', re.IGNORECASE]
}

class Converter:
	"""Convert qua lai giua mot so bang ma cua Vietnam"""
	def __init__(self):
		"""Khoi tao"""
		self.TCVN3 = ["Aµ", "A¸", "¢" , "A·", "EÌ", "EÐ", "£" , "I×", "IÝ", "Oß",
			"Oã", "¤" , "Oâ", "Uï", "Uó", "Yý", "µ" , "¸" , "©" , "·" ,
			"Ì" , "Ð" , "ª" , "×" , "Ý" , "ß" , "ã" , "«" , "â" , "ï" ,
			"ó" , "ý" , "¡" , "¨" , "§" , "®" , "IÜ", "Ü" , "Uò", "ò" ,
			"¥" , "¬" , "¦" , "­"  , "A¹", "¹" , "A¶", "¶" , "¢Ê", "Ê" ,
			"¢Ç", "Ç" , "¢È", "È" , "¢É", "É" , "¢Ë", "Ë" , "¡¾", "¾" ,
			"¡»", "»" , "¡¼", "¼" , "¡½", "½" , "¡Æ", "Æ" , "EÑ", "Ñ" ,
			"EÎ", "Î" , "EÏ", "Ï" , "£Õ", "Õ" , "£Ò", "Ò" , "£Ó", "Ó" ,
			"£Ô", "Ô" , "£Ö", "Ö" , "IØ", "Ø" , "IÞ", "Þ" , "Oä", "ä" ,
			"Oá", "á" , "¤è", "è" , "¤å", "å" , "¤æ", "æ" , "¤ç", "ç" ,
			"¤é", "é" , "¥í", "í" , "¥ê", "ê" , "¥ë", "ë" , "¥ì", "ì" ,
			"¥î", "î" , "Uô", "ô" , "Uñ", "ñ" , "¦ø", "ø" , "¦õ", "õ" ,
			"¦ö", "ö" , "¦÷", "÷" , "¦ù", "ù" , "Yú", "ú" , "Yþ", "þ" ,
			"Yû", "û" , "Yü", "ü" , "."]
			
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

		self.VIQR = ["A`" , "A'" , "A^" , "A~" , "E`" , "E'" , "E^" , "I`" , "I'" , "O`" ,
			"O'" , "O^" , "O~" , "U`" , "U'" , "Y'" , "a`" , "a'" , "a^" , "a~" ,
			"e`" , "e'" , "e^" , "i`" , "i'" , "o`" , "o'" , "o^" , "o~" , "u`" ,
			"u'" , "y'" , "A(" , "a(" , "DD" , "dd" , "I~" , "i~" , "U~" , "u~" ,
			"O+" , "o+" , "U+" , "u+" , "A." , "a." , "A?" , "a?" , "A^'", "a^'",
			"A^`", "a^`", "A^?", "a^?", "A^~", "a^~", "A^.", "a^.", "A('", "a('",
			"A(`", "a(`", "A(?", "a(?", "A(~", "a(~", "A(.", "a(.", "E." , "e." ,
			"E?" , "e?" , "E~" , "e~" , "E^'", "e^'", "E^`", "e^`", "E^?", "e^?",
			"E^~", "e^~", "E^.", "e^.", "I?" , "i?" , "I." , "i." , "O." , "o." ,
			"O?" , "o?" , "O^'", "o^'", "O^`", "o^`", "O^?", "o^?", "O^~", "o^~",
			"O^.", "o^.", "O+'", "o+'", "O+`", "o+`", "O+?", "o+?", "O+~", "o+~",
			"O+.", "o+.", "U." , "u." , "U?" , "u?" , "U+'", "u+'", "U+`", "u+`",
			"U+?", "u+?", "U+~", "u+~", "U+.", "u+.", "Y`" , "y`" , "Y." , "y." ,
			"Y?" , "y?" , "Y~" , "y~" , "\\."]

		self.VNI_WIN = ["AØ", "AÙ", "AÂ", "AÕ", "EØ", "EÙ", "EÂ", "Ì" , "Í" , "OØ",
			"OÙ", "OÂ", "OÕ", "UØ", "UÙ", "YÙ", "aø", "aù", "aâ", "aõ",
			"eø", "eù", "eâ", "ì" , "í" , "oø", "où", "oâ", "oõ", "uø",
			"uù", "yù", "AÊ", "aê", "Ñ" , "ñ" , "Ó" , "ó" , "UÕ", "uõ",
			"Ô" , "ô" , "Ö" , "ö" , "AÏ", "aï", "AÛ", "aû", "AÁ", "aá",
			"AÀ", "aà", "AÅ", "aå", "AÃ", "aã", "AÄ", "aä", "AÉ", "aé",
			"AÈ", "aè", "AÚ", "aú", "AÜ", "aü", "AË", "aë", "EÏ", "eï",
			"EÛ", "eû", "EÕ", "eõ", "EÁ", "eá", "EÀ", "eà", "EÅ", "eå",
			"EÃ", "eã", "EÄ", "eä", "Æ" , "æ" , "Ò" , "ò" , "OÏ", "oï",
			"OÛ", "oû", "OÁ", "oá", "OÀ", "oà", "OÅ", "oå", "OÃ", "oã",
			"OÄ", "oä", "ÔÙ", "ôù", "ÔØ", "ôø", "ÔÛ", "ôû", "ÔÕ", "ôõ",
			"ÔÏ", "ôï", "UÏ", "uï", "UÛ", "uû", "ÖÙ", "öù", "ÖØ", "öø",
			"ÖÛ", "öû", "ÖÕ", "öõ", "ÖÏ", "öï", "YØ", "yø", "Î" , "î" ,
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

	def convert(self, str_original, target_charset = "UNICODE", source_charset = None):
		
		if(source_charset == None):
			source_charset = self.detectCharset(str_original)

		if(source_charset == None):
			raise TypeError("Can not get charset of str_original")

		source_charset = getattr(self,source_charset)
		target_charset = getattr(self,target_charset)

		map_length = len(source_charset)
		for number in range(map_length):
			str_original = str_original.replace(source_charset[number], "::" + str(number) + "::")

		for number in range(map_length):
			str_original = str_original.replace("::" + str(number) + "::", target_charset[number])

		return str_original

	def detectCharset(self, str_input):
		for pattern in patterns:
			match = re.search(patterns[pattern][0], str_input, patterns[pattern][1])
			if(match != None):
				return pattern
		return None


def compound_unicode(unicode_str) -> str:
	"""
	Chuyển đổi chuỗi Unicode Tổ Hợp sang Unicode Dựng Sẵn
	Edited from: `https://gist.github.com/redphx/9320735`
	"""
	unicode_str = unicode_str.replace("\u0065\u0309", "\u1EBB")    # ẻ
	unicode_str = unicode_str.replace("\u0065\u0301", "\u00E9")    # é
	unicode_str = unicode_str.replace("\u0065\u0300", "\u00E8")    # è
	unicode_str = unicode_str.replace("\u0065\u0323", "\u1EB9")    # ẹ
	unicode_str = unicode_str.replace("\u0065\u0303", "\u1EBD")    # ẽ
	unicode_str = unicode_str.replace("\u00EA\u0309", "\u1EC3")    # ể
	unicode_str = unicode_str.replace("\u00EA\u0301", "\u1EBF")    # ế
	unicode_str = unicode_str.replace("\u00EA\u0300", "\u1EC1")    # ề
	unicode_str = unicode_str.replace("\u00EA\u0323", "\u1EC7")    # ệ
	unicode_str = unicode_str.replace("\u00EA\u0303", "\u1EC5")    # ễ
	unicode_str = unicode_str.replace("\u0079\u0309", "\u1EF7")    # ỷ
	unicode_str = unicode_str.replace("\u0079\u0301", "\u00FD")    # ý
	unicode_str = unicode_str.replace("\u0079\u0300", "\u1EF3")    # ỳ
	unicode_str = unicode_str.replace("\u0079\u0323", "\u1EF5")    # ỵ
	unicode_str = unicode_str.replace("\u0079\u0303", "\u1EF9")    # ỹ
	unicode_str = unicode_str.replace("\u0075\u0309", "\u1EE7")    # ủ
	unicode_str = unicode_str.replace("\u0075\u0301", "\u00FA")    # ú
	unicode_str = unicode_str.replace("\u0075\u0300", "\u00F9")    # ù
	unicode_str = unicode_str.replace("\u0075\u0323", "\u1EE5")    # ụ
	unicode_str = unicode_str.replace("\u0075\u0303", "\u0169")    # ũ
	unicode_str = unicode_str.replace("\u01B0\u0309", "\u1EED")    # ử
	unicode_str = unicode_str.replace("\u01B0\u0301", "\u1EE9")    # ứ
	unicode_str = unicode_str.replace("\u01B0\u0300", "\u1EEB")    # ừ
	unicode_str = unicode_str.replace("\u01B0\u0323", "\u1EF1")    # ự
	unicode_str = unicode_str.replace("\u01B0\u0303", "\u1EEF")    # ữ
	unicode_str = unicode_str.replace("\u0069\u0309", "\u1EC9")    # ỉ
	unicode_str = unicode_str.replace("\u0069\u0301", "\u00ED")    # í
	unicode_str = unicode_str.replace("\u0069\u0300", "\u00EC")    # ì
	unicode_str = unicode_str.replace("\u0069\u0323", "\u1ECB")    # ị
	unicode_str = unicode_str.replace("\u0069\u0303", "\u0129")    # ĩ
	unicode_str = unicode_str.replace("\u006F\u0309", "\u1ECF")    # ỏ
	unicode_str = unicode_str.replace("\u006F\u0301", "\u00F3")    # ó
	unicode_str = unicode_str.replace("\u006F\u0300", "\u00F2")    # ò
	unicode_str = unicode_str.replace("\u006F\u0323", "\u1ECD")    # ọ
	unicode_str = unicode_str.replace("\u006F\u0303", "\u00F5")    # õ
	unicode_str = unicode_str.replace("\u01A1\u0309", "\u1EDF")    # ở
	unicode_str = unicode_str.replace("\u01A1\u0301", "\u1EDB")    # ớ
	unicode_str = unicode_str.replace("\u01A1\u0300", "\u1EDD")    # ờ
	unicode_str = unicode_str.replace("\u01A1\u0323", "\u1EE3")    # ợ
	unicode_str = unicode_str.replace("\u01A1\u0303", "\u1EE1")    # ỡ
	unicode_str = unicode_str.replace("\u00F4\u0309", "\u1ED5")    # ổ
	unicode_str = unicode_str.replace("\u00F4\u0301", "\u1ED1")    # ố
	unicode_str = unicode_str.replace("\u00F4\u0300", "\u1ED3")    # ồ
	unicode_str = unicode_str.replace("\u00F4\u0323", "\u1ED9")    # ộ
	unicode_str = unicode_str.replace("\u00F4\u0303", "\u1ED7")    # ỗ
	unicode_str = unicode_str.replace("\u0061\u0309", "\u1EA3")    # ả
	unicode_str = unicode_str.replace("\u0061\u0301", "\u00E1")    # á
	unicode_str = unicode_str.replace("\u0061\u0300", "\u00E0")    # à
	unicode_str = unicode_str.replace("\u0061\u0323", "\u1EA1")    # ạ
	unicode_str = unicode_str.replace("\u0061\u0303", "\u00E3")    # ã
	unicode_str = unicode_str.replace("\u0103\u0309", "\u1EB3")    # ẳ
	unicode_str = unicode_str.replace("\u0103\u0301", "\u1EAF")    # ắ
	unicode_str = unicode_str.replace("\u0103\u0300", "\u1EB1")    # ằ
	unicode_str = unicode_str.replace("\u0103\u0323", "\u1EB7")    # ặ
	unicode_str = unicode_str.replace("\u0103\u0303", "\u1EB5")    # ẵ
	unicode_str = unicode_str.replace("\u00E2\u0309", "\u1EA9")    # ẩ
	unicode_str = unicode_str.replace("\u00E2\u0301", "\u1EA5")    # ấ
	unicode_str = unicode_str.replace("\u00E2\u0300", "\u1EA7")    # ầ
	unicode_str = unicode_str.replace("\u00E2\u0323", "\u1EAD")    # ậ
	unicode_str = unicode_str.replace("\u00E2\u0303", "\u1EAB")    # ẫ
	unicode_str = unicode_str.replace("\u0045\u0309", "\u1EBA")    # Ẻ
	unicode_str = unicode_str.replace("\u0045\u0301", "\u00C9")    # É
	unicode_str = unicode_str.replace("\u0045\u0300", "\u00C8")    # È
	unicode_str = unicode_str.replace("\u0045\u0323", "\u1EB8")    # Ẹ
	unicode_str = unicode_str.replace("\u0045\u0303", "\u1EBC")    # Ẽ
	unicode_str = unicode_str.replace("\u00CA\u0309", "\u1EC2")    # Ể
	unicode_str = unicode_str.replace("\u00CA\u0301", "\u1EBE")    # Ế
	unicode_str = unicode_str.replace("\u00CA\u0300", "\u1EC0")    # Ề
	unicode_str = unicode_str.replace("\u00CA\u0323", "\u1EC6")    # Ệ
	unicode_str = unicode_str.replace("\u00CA\u0303", "\u1EC4")    # Ễ
	unicode_str = unicode_str.replace("\u0059\u0309", "\u1EF6")    # Ỷ
	unicode_str = unicode_str.replace("\u0059\u0301", "\u00DD")    # Ý
	unicode_str = unicode_str.replace("\u0059\u0300", "\u1EF2")    # Ỳ
	unicode_str = unicode_str.replace("\u0059\u0323", "\u1EF4")    # Ỵ
	unicode_str = unicode_str.replace("\u0059\u0303", "\u1EF8")    # Ỹ
	unicode_str = unicode_str.replace("\u0055\u0309", "\u1EE6")    # Ủ
	unicode_str = unicode_str.replace("\u0055\u0301", "\u00DA")    # Ú
	unicode_str = unicode_str.replace("\u0055\u0300", "\u00D9")    # Ù
	unicode_str = unicode_str.replace("\u0055\u0323", "\u1EE4")    # Ụ
	unicode_str = unicode_str.replace("\u0055\u0303", "\u0168")    # Ũ
	unicode_str = unicode_str.replace("\u01AF\u0309", "\u1EEC")    # Ử
	unicode_str = unicode_str.replace("\u01AF\u0301", "\u1EE8")    # Ứ
	unicode_str = unicode_str.replace("\u01AF\u0300", "\u1EEA")    # Ừ
	unicode_str = unicode_str.replace("\u01AF\u0323", "\u1EF0")    # Ự
	unicode_str = unicode_str.replace("\u01AF\u0303", "\u1EEE")    # Ữ
	unicode_str = unicode_str.replace("\u0049\u0309", "\u1EC8")    # Ỉ
	unicode_str = unicode_str.replace("\u0049\u0301", "\u00CD")    # Í
	unicode_str = unicode_str.replace("\u0049\u0300", "\u00CC")    # Ì
	unicode_str = unicode_str.replace("\u0049\u0323", "\u1ECA")    # Ị
	unicode_str = unicode_str.replace("\u0049\u0303", "\u0128")    # Ĩ
	unicode_str = unicode_str.replace("\u004F\u0309", "\u1ECE")    # Ỏ
	unicode_str = unicode_str.replace("\u004F\u0301", "\u00D3")    # Ó
	unicode_str = unicode_str.replace("\u004F\u0300", "\u00D2")    # Ò
	unicode_str = unicode_str.replace("\u004F\u0323", "\u1ECC")    # Ọ
	unicode_str = unicode_str.replace("\u004F\u0303", "\u00D5")    # Õ
	unicode_str = unicode_str.replace("\u01A0\u0309", "\u1EDE")    # Ở
	unicode_str = unicode_str.replace("\u01A0\u0301", "\u1EDA")    # Ớ
	unicode_str = unicode_str.replace("\u01A0\u0300", "\u1EDC")    # Ờ
	unicode_str = unicode_str.replace("\u01A0\u0323", "\u1EE2")    # Ợ
	unicode_str = unicode_str.replace("\u01A0\u0303", "\u1EE0")    # Ỡ
	unicode_str = unicode_str.replace("\u00D4\u0309", "\u1ED4")    # Ổ
	unicode_str = unicode_str.replace("\u00D4\u0301", "\u1ED0")    # Ố
	unicode_str = unicode_str.replace("\u00D4\u0300", "\u1ED2")    # Ồ
	unicode_str = unicode_str.replace("\u00D4\u0323", "\u1ED8")    # Ộ
	unicode_str = unicode_str.replace("\u00D4\u0303", "\u1ED6")    # Ỗ
	unicode_str = unicode_str.replace("\u0041\u0309", "\u1EA2")    # Ả
	unicode_str = unicode_str.replace("\u0041\u0301", "\u00C1")    # Á
	unicode_str = unicode_str.replace("\u0041\u0300", "\u00C0")    # À
	unicode_str = unicode_str.replace("\u0041\u0323", "\u1EA0")    # Ạ
	unicode_str = unicode_str.replace("\u0041\u0303", "\u00C3")    # Ã
	unicode_str = unicode_str.replace("\u0102\u0309", "\u1EB2")    # Ẳ
	unicode_str = unicode_str.replace("\u0102\u0301", "\u1EAE")    # Ắ
	unicode_str = unicode_str.replace("\u0102\u0300", "\u1EB0")    # Ằ
	unicode_str = unicode_str.replace("\u0102\u0323", "\u1EB6")    # Ặ
	unicode_str = unicode_str.replace("\u0102\u0303", "\u1EB4")    # Ẵ
	unicode_str = unicode_str.replace("\u00C2\u0309", "\u1EA8")    # Ẩ
	unicode_str = unicode_str.replace("\u00C2\u0301", "\u1EA4")    # Ấ
	unicode_str = unicode_str.replace("\u00C2\u0300", "\u1EA6")    # Ầ
	unicode_str = unicode_str.replace("\u00C2\u0323", "\u1EAC")    # Ậ
	unicode_str = unicode_str.replace("\u00C2\u0303", "\u1EAA")    # Ẫ
	return unicode_str


folder_path = r"C:\Users\quoct\Downloads\Slide_NLLTCT"
exts = [".xml"]

if __name__ == "__main__":
	converter = Converter()

	for root, dirs, files in os.walk(folder_path):
		for file in files:
			if any(ext in file for ext in exts):
				file_path = os.path.join(root, file)

				print(f"Dang xu ly tap tin {file}...")

				data = []
				reader = open(file_path, encoding="utf-8", mode="r")
				for line in reader:
					data.append(compound_unicode(line).strip())
				reader.close()

				writer = open(file_path, encoding="utf-8", mode="w")
				data = "\n".join(data)
				writer.write(data)
				writer.close()
				print(f"Da xu ly xong tap tin {file}")
