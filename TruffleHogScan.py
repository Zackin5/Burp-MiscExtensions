from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import math

# TruffleHog regex strings
tokenSeparatorReg = r'[\'\"\s\r\n:=]*'

truffleRegexes = {
    'Slack Token': r'(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
    'RSA private key': r'-----BEGIN RSA PRIVATE KEY-----',
    'SSH (DSA) private key': r'-----BEGIN DSA PRIVATE KEY-----',
    'SSH (EC) private key': r'-----BEGIN EC PRIVATE KEY-----',
    'PGP private key block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'AWS API Key': r'((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})',
    'Amazon MWS Auth Token': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'AWS AppSync GraphQL Key': r'da2-[a-z0-9]{26}',
    'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'Facebook OAuth': r'[fF][aA][cC][eE][bB][oO][oO][kK]' + tokenSeparatorReg + r'[\'|\"][0-9a-f]{32}[\'|\"]',
    'GitHub': r'[gG][iI][tT][hH][uU][bB]' + tokenSeparatorReg + r'[\'|\"][0-9a-zA-Z]{35,40}[\'|\"]',
    'Generic API Key': r'[aA][pP][iI]_?[kK][eE][yY]' + tokenSeparatorReg + r'[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]',
    # 'Generic Secret': r'[sS][eE][cC][rR][eE][tT].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]',
    'Generic Secret': r'(?:pass|token|cred|secret|key)' + tokenSeparatorReg + r'[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth Client ID': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    #'Google Cloud Platform API Key': r'AIza[0-9A-Za-z\-_]{35}',
    #'Google Cloud Platform OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    #'Google Drive API Key': r'AIza[0-9A-Za-z\-_]{35}',
    #'Google Drive OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Google (GCP) Service-account': r'\"type\": \"service_account\"',
    #'Google Gmail API Key': r'AIza[0-9A-Za-z\-_]{35}',
    #'Google Gmail OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    #'Google OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
    #'Google YouTube API Key': r'AIza[0-9A-Za-z\-_]{35}',
    #'Google YouTube OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Heroku API Key': r'[hH][eE][rR][oO][kK][uU]' + tokenSeparatorReg + r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
    'Password in URL': r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"\'\s]',
    'PayPal Braintree Access Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Picatic API Key': r'sk_live_[0-9a-z]{32}',
    'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Restricted API Key': r'rk_live_[0-9a-zA-Z]{24}',
    'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
    'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
    'Telegram Bot API Key': r'[0-9]+:AA[0-9A-Za-z\-_]{33}',
    'Twilio API Key': r'SK[0-9a-fA-F]{32}',
    'Twitter Access Token': r'[tT][wW][iI][tT][tT][eE][rR]' + tokenSeparatorReg + r'[1-9][0-9]+-[0-9a-zA-Z]{40}',
    'Twitter OAuth': r'[tT][wW][iI][tT][tT][eE][rR]' + tokenSeparatorReg + r'[\'|\"][0-9a-zA-Z]{35,44}[\'|\"]#',
    #'JWT Token': r'[="\'\s][0-9a-zA-Z_=+/,-]{8,}\.[0-9a-zA-Z_=+/,-]{8,}\.[0-9a-zA-Z_=+/,-]*[;"\'\s\n\r]'
}

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

class BurpExtender(IBurpExtender, IScannerCheck):

    # Init
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("TruffleHog Scanner Checks")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

        # Compile truffleHog regex objects
        self._regex = {}

        for key in truffleRegexes:
            self._regex[key] = re.compile(truffleRegexes[key])

    # TruffleHog Regex rule implementation
    def truffle_regex_check(self, baseRequestResponse):

        regexIssues = list()
        # Scan response body for regex matches
        for key in self._regex:
            response_string = self._helpers.bytesToString(baseRequestResponse.getResponse())

            # Find and report regex matches in response body
            regex_str_matches = []
            regex_match_ranges = []
            for regexMatch in self._regex[key].finditer(response_string):
                regex_str_matches.append(self.truncateMatchStr(regexMatch.group(0)))  # Matched string
                regex_match_ranges.append([regexMatch.start(0), regexMatch.end(0)])  # Range

            # Move to next regex key if no results
            if len(regex_str_matches) == 0:
                continue

            # Add results to issue list
            sorted_ranges = [array('i', range) for range in self.sortRangeList(regex_match_ranges)]
            regexIssues.append(TruffleHogScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, sorted_ranges)],
                    "(TruffleHog) Exposed {}{}".format(key, self.getPluralS(regex_str_matches)),
                    "Detected {}{}: {}".format(key, self.getPluralS(regex_str_matches), ', '.join(regex_str_matches)),
                    "Information",
                    "Firm"))

        return regexIssues

    # TruffleHog Entropy rule implementation
    def find_entropy(self, baseRequestResponse):
        entropyIssues = list()

        # convert response stream
        response_string = self._helpers.bytesToString(baseRequestResponse.getResponse())

        entropyIssues.append(self.find_base64_entropy(baseRequestResponse, response_string))
        entropyIssues.append(self.find_hex_entropy(baseRequestResponse, response_string)) 

        return entropyIssues


    def find_base64_entropy(self, baseRequestResponse, response_string):
        base64_strings = self.get_strings_of_set(response_string, BASE64_CHARS)

        entroStringFindings = {}
        
        # Scan response body for entropy strings
        for entroString in base64_strings:
            b64Entropy = self.shannon_entropy(entroString.word, BASE64_CHARS)
            if b64Entropy > 4.5:
                entroStringFindings[entroString.word] = entroString.range

        # No results, exit early
        if len(entroStringFindings) == 0:
            return None

        # Format issue finding
        entropyStrs = [self.truncateMatchStr(key) for key in entroStringFindings]
        entropyRanges = [array('i', range) for range in self.sortRangeList(v for v in entroStringFindings.values())]

        return TruffleHogScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, entropyRanges)],
            "(TruffleHog) High Entropy Base64 string{}".format(self.getPluralS(entropyStrs)),
            "High Entropy Base64 string{}: {}".format(self.getPluralS(entropyStrs), ', '.join(entropyStrs)),
            "Information",
            "Tentative")


    def find_hex_entropy(self, baseRequestResponse, response_string):
        hex_strings = self.get_strings_of_set(response_string, HEX_CHARS)

        entroStringFindings = {}
        
        # Scan response body for entropy strings
        for entroString in hex_strings:
            hexEntropy = self.shannon_entropy(entroString.word, HEX_CHARS)
            if hexEntropy > 3:
                entroStringFindings[entroString.word] = entroString.range

        # No results, exit early
        if len(entroStringFindings) == 0:
            return None

        # Format issue finding
        entropyStrs = [self.truncateMatchStr(key) for key in entroStringFindings]
        entropyRanges = [array('i', range) for range in self.sortRangeList(v for v in entroStringFindings.values())]

        return TruffleHogScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(baseRequestResponse, None, entropyRanges)],
                "(TruffleHog) High Entropy Hex string{}".format(self.getPluralS(entropyStrs)),
                "High Entropy Hex string{}: {}".format(self.getPluralS(entropyStrs), ', '.join(entropyStrs)),
                "Information",
                "Tentative")


    def get_strings_of_set(self, word, char_set, threshold=20):
        count = 0
        workingString = entropyString()
        strings = []
        for index, char in enumerate(word):
            if char in char_set:
                workingString.word += char
                count += 1
                workingString.range = [index - count + 1, index + 1]
            else:
                if count > threshold:
                    strings.append(workingString)
                workingString = entropyString()
                count = 0

        if count > threshold:
            strings.append(workingString)

        return strings


    def shannon_entropy(self, data, iterator):
        """
        Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        """
        if not data:
            return 0
        entropy = 0
        for x in iterator:
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy


    def overlap(self, x, y):
        return  bool(len( range(max(x[0],y[0]), min(x[1], y[1])+1  ) ))


    def sortRangeList(self, lst):
        '''
        Sorts range list and removes overlaps. 
        Nicked from https://stackoverflow.com/questions/74861529/remove-overlaping-tuple-ranges-from-list-leaving-only-the-longest-range
        '''
        sorted_lst = sorted(lst, key=lambda x: x[0])
        diff = lambda x: abs(x[0]-x[1])
        result = [sorted_lst[0]]
        for x in sorted_lst[1:]:
            if self.overlap(result[-1], x):
                if diff(result[-1]) == diff(x):
                    result.append(x)
                else:
                    result[-1] = max(result[-1], x, key=diff)
            else:
                result.append(x)
        return result


    def getPluralS(self, lst):
        '''
        Returns S if list contains elements
        '''
        return 's' if len(lst) > 1 else ''


    def truncateMatchStr(self, string):
        '''
        Truncates long match strings for display
        '''
        max_length = 256
        return ('"' + string[:max_length] + '...') if len(string) > max_length + 3 else '"{}\"'.format(string)


    # Scan events hook
    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        issueResults = self.truffle_regex_check(baseRequestResponse)

        # entropy strings check
        issueResults.extend(self.find_entropy(baseRequestResponse))

        return issueResults


    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # look for matches of our passive check grep string
        issueResults = self.truffle_regex_check(baseRequestResponse)

        # entropy strings check
        issueResults.extend(self.find_entropy(baseRequestResponse))

        # TODO: git dir checks?
        return issueResults


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if (existingIssue.getIssueName() == newIssue.getIssueName() and
            existingIssue.getRemediationDetail() == newIssue.getRemediationDetail()):
            return -1

        return 0


class entropyString():
    range = [-1,-1]
    word = ""


class TruffleHogScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService