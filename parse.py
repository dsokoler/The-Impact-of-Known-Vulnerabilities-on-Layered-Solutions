#TQDM is the progress bar
from tqdm import tqdm
import sys, getopt

#Numpy is a dependency of MatPlotLib
try:
	import numpy;
except ImportError:
	print("Please install NumPy: \"pip install numpy\"");
	sys.exit(1);

#MatPlotLib is for the visualization
try:
	import matplotlib.pyplot as plt;
except ImportError:
	print("Please install MatPlotLib: \"pip install matplotlib\"");
	sys.exit(1);

#Pandas is for datetimes
try:
	import pandas as pd
except ImportError:
	print("Please install Pandas: \"pip install pandas\"");
	sys.exit(1);

#lxml is a more advanced xml processor
try:
	from lxml import etree
except ImportError:
	import xml.etree.ElementTree as etree



totalVulnerabilities = 0;



#Namespaces for NVD CVE
namespace = {'entry': 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
	  		 'cvss': 'http://scap.nist.gov/schema/cvss-v2/0.2',
	  		 'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4',
	  		 'scap-core': 'http://scap.nist.gov/schema/scap-core/0.1',
	  		 'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
	  		 'patch': 'http://scap.nist.gov/schema/patch/0.1',
	  		 'cpe-lang': 'http://cpe.mitre.org/language/2.0'}



#Names of each xml file to parse
fileNames = ['nvdcve-2.0-2002.xml', 'nvdcve-2.0-2003.xml', 'nvdcve-2.0-2004.xml', 'nvdcve-2.0-2005.xml', 
			 'nvdcve-2.0-2006.xml', 'nvdcve-2.0-2007.xml', 'nvdcve-2.0-2008.xml', 'nvdcve-2.0-2009.xml', 
			 'nvdcve-2.0-2010.xml', 'nvdcve-2.0-2011.xml', 'nvdcve-2.0-2012.xml', 'nvdcve-2.0-2013.xml', 
			 'nvdcve-2.0-2014.xml', 'nvdcve-2.0-2015.xml', 'nvdcve-2.0-2016.xml']



#Include CVSS description and levels here
helpText 	= """
	0				1				2
--av	LOCAL				ADJACENT_NETWORK	\tNETWORK
--ac	HIGH 				MEDIUM				LOW
--auth	MULTIPLE_INSTANCES	\tSINGLE_INSTANCE		\tNONE
--conf	NONE				PARTIAL				COMPLETE
--int	NONE				PARTIAL				COMPLETE
--avail	NONE				PARTIAL				COMPLETE
--layers: a tag to specify the relevant layers of the solution
	The --layers tag should be input as a commma separated list should be bound by quotes (--layers="L1,L2,L3,...")
	The layers themselves should be in the form of "Company Product Version" (e.g. Oracle Goldengate 11.2)
	Spaces within company, product, or version should be input as underscores.  The only spaces in the input should be between company product and version.
""";



aboutText 	= """Produced as part of the INSuRE Project at Purdue University, Spring 2016 by Robert Haverkos and Daniel Sokoler
Professors: Dr. Melissa Dark, Dr. John Springer
Technical Directors: Trent Pitsenbarger, Bill Layton""";



class Vulnerability:
	"""
	Holds all info for a relevant vulnerability
	"""

	def __init__(self, cve, products, datePublished, datePatched, cvss, cwe, references, summary):
		self.cve 			= cve;				#CVE identifier for this vulnerability
		self.products 		= products;			#a list containing the names of all products affected
		self.datePublished 	= datePublished;	#the date this vulnerability was published (YYYY-MM-DD)
		self.datePatched 	= datePatched;		#the date this vulnerability was patched (YYYY-MM-DD)
		self.cvss 			= cvss;				#a CVSS object representing this vulnerability's CVSS information
		self.cwe 			= cwe;				#A CWE identifier for this vulnerability
		self.references		= references;		# a list of the references (strings)
		self.summary 		= summary;			#A brief summary of this vulnerability

	def printVuln(self):
		if (self.cve == None):
			print("No CVE");
		else:
			print(self.cve);

		print("Products: ", end="");
		if (self.products == None):
			print("None");
		else:
			print();
			for product in self.products:
				print("  " + product);

		print("Date Published: ", end="");
		if (self.datePublished == None):
			print("None");
		else:
			print(self.datePublished);

		print("Date patched: ", end="");
		if (self.datePatched == None):
			print("None");
		else:
			print(self.datePatched);

		print("CVSS Information: ", end="");
		if (self.cvss == None):
			print("None");
		else:
			print();
			self.cvss.printCVSS();

		print("references: ", end="");
		if (self.references == None):
			print("None");
		else:
			print();
			for reference in self.references:
				print("  " + reference);

		print("Summary: ", end="");
		if (self.summary == None):
			print("None");
		else:
			print(self.summary);

		print();



class CVSS:
	"""
	Holds all information about the cvss score regarding a specific vulnerability
	Ratings:
	-0: 
	 -Access Vector: LOCAL
	 -Access Complexity: HIGH
	 -Authentication: MULTIPLE
	 -Impact: NONE
	-1: 
	 -Access Vector: ADJACENT_NETWORK
	 -Access Complexity: MEDIUM
	 -Authentication: SINGLE_INSTANCE
	 -Impact: PARTIAL
	-2: 
	 -Access Vector: NETWORK
	 -Access Complexity: LOW
	 -Authentication: NONE
	 -Impact: COMPLETE
	"""
	def __init__(self, score, vector, complexity, authentication, confidentiality, integrity, availability):
		self.score 				= (score);										#CVSS score
		self.vector 			= getExploitabilityRating(vector);				#CVSS access vector
		self.complexity 		= getExploitabilityRating(complexity);			#CVSS access complexity
		self.authentication 	= getExploitabilityRating(authentication);		#CVSS authentication rating
		self.confidentiality 	= getImpactMetrics(confidentiality);			#CVSS confidentiality impact rating
		self.integrity 			= getImpactMetrics(integrity);					#CVSS integrity impact rating
		self.availability 		= getImpactMetrics(availability);				#CVSS availability impact rating

	def printCVSS(self):
		print("  Score: ", end="");
		if (self.score == None):
			print("None");
		else:
			print(str(self.score));

		print("  Vector: ", end="");
		if (self.vector == None):
			print("None");
		else:
			print(str(self.vector));

		print("  Complexity: ", end="");
		if (self.complexity == None):
			print("None");
		else:
			print(str(self.complexity));

		print("  Authentication: ", end="");
		if (self.authentication == None):
			print("None");
		else:
			print(str(self.authentication));

		print("  Confidentiality: ", end="");
		if (self.confidentiality == None):
			print("None");
		else:
			print(str(self.confidentiality));

		print("  Integrity: ", end="");
		if (self.integrity == None):
			print("None");
		else:
			print(str(self.integrity));

		print("  Availability: ", end="");
		if (self.availability == None):
			print("None");
		else:
			print(str(self.availability));



#Convert the string values of exploitability ratings to their numerical value
def getExploitabilityRating(attribute):
	if (attribute == "LOCAL" or attribute == "HIGH" or attribute == "MULTIPLE_INSTANCES"):
		return 0;
	elif (attribute == "ADJACENT_NETWORK" or attribute == "MEDIUM" or attribute == "SINGLE_INSTANCE"):
		return 1;
	elif (attribute == "NETWORK" or attribute == "LOW" or attribute == "NONE"):
		return 2;
	else:
		print("INCORRECT EXPLOITABILITY RATING: " + attribute)

#Convert the string value of impact metrics to their numerical value
def getImpactMetrics(attribute):
	if (attribute == "NONE"):
		return 0;
	elif(attribute == "PARTIAL"):
		return 1;
	elif(attribute == "COMPLETE"):
		return 2;
	else:
		print("INCORRECT IMPACT METRIC: " + attribute);
		return -1;



#Basic parsing of the xml file
#@param 'filename': the name of the file to parse, in string format
#returns a list of vulnerability objects
def parse(filename):
	vulnerabilityList = []
	
	#Attempt to parse the given file, catch the error if that file is not found
	try:
		tree = etree.parse(filename);
	except FileNotFoundError:
		print("Unable to open file " + filename);
		return vulnerabilityList;
		
	root = tree.getroot();


	for entry in root.findall('entry:entry', namespace):
		cveSummary = entry.find('.//vuln:summary', namespace);
		if (cveSummary != None):
			cveSummary = cveSummary.text;

		#'** REJECT **' indicates this vulnerability entry is invalid and should be ignored
		if (cveSummary != None and "** REJECT **" in cveSummary):
			continue;

		#The CVE of this vulnerability
		cveID = entry.attrib['id'];
		#print(cveID);

		#The list of vulnerable products this vulnerability affects
		productList = getProducts(entry);

		#The date this vulnerability was published (YYYY-MM-DD)
		datePublished = entry.find('.//vuln:published-datetime', namespace);

		#Validate the date this vulnerability was published
		if (datePublished == None):
			datePublished = "No Publish Date";
		else:
			datePublishedText 	= datePublished.text;
			datePublished 		= datePublishedText.split('T', 1)[0];

		#Holds all the information regarding this vulnerability's CVSS score
		cvssObject = getCVSS(entry);

		#The CWE identifier for this vulnerability
		cweID = getCWE(entry);

		#A list of all URL references for this vulnerability
		referenceList = getReferences(entry);

		vulnerability = Vulnerability(cveID, productList, datePublished, None,
									  cvssObject, cweID, referenceList, cveSummary);

		#Store this vulnerability
		vulnerabilityList.append(vulnerability);

		global totalVulnerabilities;
		totalVulnerabilities += 1;

	return vulnerabilityList;
	


#Gathers the information on the cvss ratings of this vulnerability
def getCVSS(entry):
	cvss = entry.find('.//vuln:cvss', namespace);
	if (cvss == None):
		return None;

	cvssScore 			= float(entry.find('.//vuln:cvss/cvss:base_metrics/cvss:score', namespace).text);
	cvssAccess 			= entry.find('.//vuln:cvss/cvss:base_metrics/cvss:access-vector', namespace).text;
	cvssComplexity 		= entry.find('.//vuln:cvss/cvss:base_metrics/cvss:access-complexity', namespace).text;
	cvssAuthentication 	= entry.find('.//vuln:cvss/cvss:base_metrics/cvss:authentication', namespace).text;
	cvssConfidentiality = entry.find('.//vuln:cvss/cvss:base_metrics/cvss:confidentiality-impact', namespace).text;
	cvssIntegrity 		= entry.find('.//vuln:cvss/cvss:base_metrics/cvss:integrity-impact', namespace).text;
	cvssAvailability 	= entry.find('.//vuln:cvss/cvss:base_metrics/cvss:availability-impact', namespace).text;

	#Create the CVSS object for this vulnerability
	cvssObject = CVSS(cvssScore, cvssAccess, cvssComplexity, cvssAuthentication, cvssConfidentiality, cvssIntegrity, cvssAvailability);

	return cvssObject;



#Returns the list of URLs for the references (hopefully these are patch notes)
def getReferences(entry):
	referenceList = [];
	for reference in entry.findall('.//vuln:references/vuln:reference', namespace):
		referenceURL = reference.attrib['href'];
		referenceList.append(referenceURL);

	return referenceList;



#Locate the CWE ID for this entry
def getCWE(entry):
	cweEntry = entry.find('.//vuln:cwe', namespace);
	if (cweEntry == None):
		return 'None';
	else:
		return cweEntry.attrib['id'];



#Returns the list of products this vulnerability affects
def getProducts(entry):
	products = [];
	productList = entry.find('.//vuln:vulnerable-software-list', namespace);

	if (productList == None):
		return None;

	for product in productList.findall('.//vuln:product', namespace):
		text = product.text;
		products.append(text);

	return products;



#Finds all vulnerabilities with 'name' in the products list
def findProducts(name, vulnerabilities):
	count = 0;
	vulnerableEntries = [];
	print();
	print("Finding all relevant vulnerabilities for \"" + name + "\": ", end="");
	for vulnerability in tqdm(vulnerabilities):
		if (vulnerability.products == None):
			continue;
		for product in vulnerability.products:
			if (name in product):
				count += 1;
				vulnerableEntries.append(vulnerability);
				break;

	print(str(count));

	return vulnerableEntries;



#Returns a list of vulnerabilities that match the criteria specified in this function's arguments
def filterVulnerabilities(vulnerabilities, minScore, minAccess, minComplexity, minAuthentication, minConfidentiality, minIntegrity, minAvailability):
	validVulnerabilities = [];

	#score, vector, complexity, authentication, confidentiality, integrity, availability
	for vulnerability in vulnerabilities:
		cvss = vulnerability.cvss;
		#print("Comparing " + cvss.score + " to " + str(minScore));
		if (cvss == None):
			continue;
		if (cvss.score < minScore):
			continue;
		if (cvss.vector < minAccess):
			continue;
		if (cvss.complexity < minComplexity):
			continue;
		if (cvss.authentication < minAuthentication):
			continue;
		if (cvss.confidentiality < minConfidentiality):
			continue;
		if (cvss.integrity < minIntegrity):
			continue;
		if (cvss.availability < minAvailability):
			continue;

		validVulnerabilities.append(vulnerability);

	return validVulnerabilities;



#Search a vulnerability's summary for a string
def filterVulnerabilitiesBySummary(vulnerabilities, filter):
	filteredVulnerabilities = [];

	for vulnerability in vulnerabilities:
		if (vulnerability.summary == None):
			continue;
		if (filter in vulnerability.summary):
			filteredVulnerabilities.append(vulnerability);

	return filteredVulnerabilities;



#Create a plot using MatPlotLib
def createTimeline(vulnerabilities):
	datesVulnerable = [];
	indices = [];
	count = 1;
	for vulnerability in vulnerabilities:
		date = pd.to_datetime(vulnerability.datePublished)
		datesVulnerable.append(date);
		indices.append(count);
		count += 1;

	fig, ax = plt.subplots(figsize=(6,1));

	#Each vulnerability on the same Y level
	#ax.scatter(datesVulnerable, [1]*len(datesVulnerable), marker='s', s=100);
	
	#Each vulnerability on it's own Y level
	ax.scatter(datesVulnerable, indices, marker='s', s=100);
	fig.autofmt_xdate();

	#Plot formatting, so it looks like a timeline
	ax.yaxis.set_visible(False)
	ax.spines['right'].set_visible(False)
	ax.spines['left'].set_visible(False)
	ax.spines['top'].set_visible(False)
	ax.xaxis.set_ticks_position('bottom')

	ax.get_yaxis().set_ticklabels([])
	day = pd.to_timedelta("1", unit='D')
	
	#This is if we want the start end end to 
	#plt.xlim(datesVulnerable[0] - day, datesVulnerable[-1] + day)
	
	#This is is we want it to go from startDate to endDate
	startDate = pd.to_datetime("January 1, 1999");
	endDate   = pd.to_datetime("December 31, 2016");
	plt.xlim(startDate, endDate);
	
	plt.show();

	#Could just have each vulenrability have many points, each point representing a day
	# that system was vulenrable (would have 10 points plotted on the same Y level if
	# there were 10 days it was vulnerable for)



#Validate (some of) the options provided on the command line 
def checkOptErr(opt, arg):
	if (arg < 0 or arg > 2):
		print();
		print("Invalid --" + opt + " option: " + str(arg));
		print("This option should be 0, 1, or 2");
		print();
		sys.exit(1);



#Main method	
#-h: 			print the help string, must be the first argument
#--score=?		lowest score that makes a vulnerability relevant
#--av=?: 		lowest level of access vector that makes a vulnerability relevant			
#--ac=?: 		lowest level of access complexity that makes a vulnerability relevant	
#--auth=?: 		lowest level of authentication that makes a vulnerability relevant		
#--conf=?: 		lowest level of confidentiality impact that makes a vulnerability relevant
#--int=?: 		lowest level of integrity impact that makes a vulnerability relevant	
#--avail=?: 	lowest level of availability impact that makes a vulnerability relevant	
#--layers=?:	a comma separated list of the layers we are interested in looking at
#--patchtime=?: the average time it takes from when a patch is released to when it is applied
#Options that begin with "--" should have their argument be a number, either 0 1 or 2
optionsList = "h";
longOptionsList = ["score=", "av=", "ac=", "auth=", "conf=", "int=", "avail=", "layers=", "patchtime="]
def main(argv):

	print();
	print(aboutText);
	print();

	#The default values for the "filter" variables
	minScore 			= 0;
	minAccess 			= 0;
	minComplexity 		= 0;
	minAuthentication 	= 0;
	minConfidentiality 	= 0;
	minIntegrity 		= 0;
	minAvailability 	= 0;
	patchTime 			= 7;

	#Get the options and their arguments from the command line
	try:
		opts, args = getopt.getopt(sys.argv[1:], optionsList, longOptionsList);
	except getopt.GetoptError as err:
		print(err);
		sys.exit(2);

	#Take the appropriate action with those arguments and validate them
	hasLayer = False;
	for opt, arg in opts:
		print("Option: " + opt + "\t\tArgument: " + arg);
		if(opt == "-h"):
			print(helpText);
			sys.exit(2);
		elif (opt == "--score"):
			minScore = float(arg);
			if (minScore < 0 or minScore > 10):
				print();
				print("Invalid --score option: " + str(minScore));
				print("This option should be between 0 and 10");
				print();
				sys.exit(1);
		elif (opt == "--av"):
			minAccess = int(arg);
			checkOptErr(opt, minAccess);
		elif (opt == "--ac"):
			minComplexity = int(arg);
			checkOptErr(opt, minComplexity);
		elif (opt == "--auth"):
			minAuthentication = int(arg);
			checkOptErr(opt, minAuthentication);
		elif (opt == "--conf"):
			minConfidentiality = int(arg);
			checkOptErr(opt, minConfidentiality);
		elif (opt == "--int"):
			minIntegrity = int(arg);
			checkOptErr(opt, minIntegrity);
		elif (opt == "--avail"):
			minAvailability = int(arg);
			checkOptErr(opt, minAvailability);
		elif (opt == "--layers"):
			layers = arg.replace(" ", ":");
			layers = layers.lower();
			layers = layers.split(',');
			hasLayer = True;
		elif (opt == "--patchtime"):
			patchTime = arg;
			if (patchTime < 0):
				print();
				print("Invalid --patchtime option: " + patchTime);
				print("this option should be a positive number");
				print();
				sys.exit(1);

	#Ensure we have a set of layers to analyze
	if (hasLayer == False):
		print("Please specify one or more layers to analyze.");
		sys.exit();

	#Holds all vulnerabilities
	vulnerabilities = [];

	#The bulk of this program, the actual gathering of data happens here, and in the parse method
	print();
	print("Analyzing NVD XML Files");
	for name in tqdm(fileNames):
		vulnerabilityList = parse(name);
		vulnerabilities.extend(vulnerabilityList);

	print("Total Vulnerabilities: " + str(totalVulnerabilities));

	#Keeps track of each set of vulnerabilities: key is the layer, value is a list of that layer's vulnerabilities
	layerVulnerabilities = {};

	#Get the vulnerabilities for each layer, filter them by the specified criteria, and visualize them
	for layer in layers:
		layerList = findProducts(layer, vulnerabilities);
		layerListFiltered = filterVulnerabilities(layerList, minScore, minAccess, minComplexity, minAuthentication, minConfidentiality, minIntegrity, minAvailability);
		layerVulnerabilities[layer] = layerList;
		if (layerListFiltered == []):
			print("No vulnerabilities for " + layer + ".");
			print();
		else:
			createTimeline(layerListFiltered);



#Ensures this only runs if parse.py is the main file called
if __name__ == "__main__":
	main(sys.argv);
