from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import math

# TruffleHog regex strings
truffleRegexes = {
    "Slack Token": "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
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

        for key in self._regex:
            response_string = self._helpers.bytesToString(baseRequestResponse.getResponse())

            # Find and report regex matches in response body
            for regexMatch in self._regex[key].finditer(response_string):
                regexIssues.append(TruffleHogScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, [array('i', [regexMatch.start(0), regexMatch.end(0)])])],
                    "(TruffleHog) Exposed {}".format(key),
                    "Detected {}: \"{}\"".format(key, regexMatch.group(0)),
                    "Information",
                    "Firm"))

        return regexIssues

    # TruffleHog Entropy rule implementation
    def find_entropy(self, baseRequestResponse):
        entropyIssues = list()

        # convert response stream
        response_string = self._helpers.bytesToString(baseRequestResponse.getResponse())
        base64_strings = self.get_strings_of_set(response_string, BASE64_CHARS)
        hex_strings = self.get_strings_of_set(response_string, HEX_CHARS)

        for entroString in base64_strings:
            b64Entropy = self.shannon_entropy(entroString.word, BASE64_CHARS)
            if b64Entropy > 4.5:
                entropyIssues.append(TruffleHogScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, [array('i', entroString.range)])],
                    "(TruffleHog) High Entropy Base64 string",
                    "High Entropy Base64 string: \"{}\"".format(entroString.word),
                    "Information",
                    "Tentative"))                
                
        for entroString in hex_strings:
            hexEntropy = self.shannon_entropy(entroString.word, HEX_CHARS)
            if hexEntropy > 3:
                entropyIssues.append(TruffleHogScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, [array('i', entroString.range)])],
                    "(TruffleHog) High Entropy Hex string",
                    "High Entropy Hex string: \"{}\"".format(entroString.word),
                    "Information",
                    "Tentative"))     

        return entropyIssues

    def get_strings_of_set(self, word, char_set, threshold=20):
        count = 0
        workingString = entropyString()
        strings = []
        for index, char in enumerate(word):
            if char in char_set:
                workingString.word += char
                count += 1
                workingString.range = [index - count, index + 1]
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
        if existingIssue.getIssueName() == newIssue.getIssueName():
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