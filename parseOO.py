#TQDM is the progress bar
from tqdm import tqdm
import sys, getopt, random, copy
import xml.dom.minidom as minidom;

#These three are for downloading and unzipping the NVD files
import requests, zipfile, io

#Numpy is a dependency of MatPlotLib
try:
	import numpy;
except ImportError:
	print("Please install NumPy: \"pip install numpy\"");
	sys.exit(1);

#Pandas is for datetimes
try:
	import pandas as pd
except ImportError:
	print("Please install Pandas: \"pip install pandas\"");
	sys.exit(1);

#MatPlotLib is for the visualization
try:
	import matplotlib.pyplot as plt;
except ImportError:
	print("Please install MatPlotLib: \"pip install matplotlib\"");
	sys.exit(1);

#lxml is a more advanced xml processor
try:
	import xml.etree.ElementTree as etree
except ImportError:
	print("Error importing ElementTree, please check your python installation");
	sys.exit(1);
print();



#The default values for the "filter" variables
minCVSS 			= None;
patchTime 			= 7;
outputFile			= "";

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



fileURLs = ['https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2015.xml.zip',
			'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.zip']



#Include CVSS description and levels here
helpText 	= """
--av: Access Vector
--ac: Access Complexity
--auth: Authentication (# of times)
--conf: the impact on the system's confidentiality
--int: the impact on the system's integrity
--avail: the impact on the system's availability

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


#Specifies information about the creation of this project
aboutText 	= """Produced as part of the INSuRE Project at Purdue University, Spring 2016 by Daniel Sokoler and Robert Haverkos
Professors: Dr. Melissa Dark, Dr. John Springer, Dr. Filipo Sharevski
Technical Director: Trent Pitsenbarger (NSA)""";



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

		#print("Date patched: ", end="");
		#if (self.datePatched == None):
			#print("None");
		#else:
			#print(self.datePatched);

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

	def compareScore(self, score):
		if (self.score <= score):
			return True;
		else:
			return False;

	def compareVector(self, vector):
		if (self.vector <= vector):
			return True;
		else:
			return False;

	def compareComplexity(self, complexity):
		if (self.complexity <= complexity):
			return True;
		else:
			return False;

	def compareAuthentication(self, authentication):
		if (self.authentication <= authentication):
			return True;
		else:
			return False;

	def compareConfidentiality(self, confidentiality):
		if (self.confidentiality <= confidentiality):
			return True;
		else:
			return False;

	def compareIntegrity(self, integrity):
		if (self.integrity <= integrity):
			return True;
		else:
			return False;

	def compareAvailability(self, availability):
		if (self.Availability <= availability):
			return True;
		else:
			return False;

	def compareCVSS(self, cvss):
		if (not self.compareScore(cvss.score)):
			return False;
		if (not self.compareVector(cvss.vector)):
			return False;
		if (not self.compareComplexity(cvss.complexity)):
			return False;
		if (not self.compareAuthentication(cvss.authentication)):
			return False;
		if (not self.compareConfidentiality(cvss.confidentiality)):
			return False;
		if (not self.compareIntegrity(cvss.integrity)):
			return False;
		if (not self.compareAuthentication(cvss.authentication)):
			return False;

		return True;





#Convert the string values of exploitability ratings to their numerical value
#@param attribute: a string representing an attribute of a vulnerability
#returns the attribute in integer form, -1 if invalid
def getExploitabilityRating(attribute):
	if (isinstance(attribute, int)):
		if (attribute < 3 and attribute > -1):
			return attribute;
		else :
			print("INCORRECT EXPLOITABILITY RATING: " + attribute)
			return -1;

	if (attribute == "LOCAL" or attribute == "HIGH" or attribute == "MULTIPLE_INSTANCES"):
		return 0;
	elif (attribute == "ADJACENT_NETWORK" or attribute == "MEDIUM" or attribute == "SINGLE_INSTANCE"):
		return 1;
	elif (attribute == "NETWORK" or attribute == "LOW" or attribute == "NONE"):
		return 2;
	else:
		print("INCORRECT EXPLOITABILITY RATING: " + attribute)
		return -1;

#Convert the string value of impact metrics to their numerical value
#@param attribute: a string representing an attribute of a vulnerability
#returns the attribute in integer form, -1 if invalid
def getImpactMetrics(attribute):
	if (isinstance(attribute, int)):
		if (attribute < 3 and attribute > -1):
			return attribute;
		else :
			print("INCORRECT EXPLOITABILITY RATING: " + attribute)
			return -1;

	if (attribute == "NONE"):
		return 0;
	elif(attribute == "PARTIAL"):
		return 1;
	elif(attribute == "COMPLETE"):
		return 2;
	else:
		print("INCORRECT IMPACT METRIC: " + attribute);
		return -1;



#Attempts to print xml in a readable format
#@param elem: the xml string to prettify
#returns a readable, tabbed, good looking xml document
def prettify(elem):
	rough_string = etree.tostring(elem, encoding='utf8', method='xml');
	reparsed = minidom.parseString(rough_string)
	return '\n'.join([line for line in reparsed.toprettyxml(indent='	').split('\n') if line.strip()])


#Basic parsing of the xml file
#@param 'layers': a list of the layers to be parsed for
#returns a dictionary of lists of vulnerability objects, one list per layer
def parse(layers):
	global minCVSS, patchTime, outputFile;

	vulnerabilityXMLRoot = None;

	vulnerabilityList = {};
	for layer in layers:
		vulnerabilityList[layer] = [];
	
	global fileNames;
	for filename in tqdm(fileNames):
		#Attempt to parse the given file, catch the error if that file is not found
		try:
			tree = etree.parse(filename);
		except FileNotFoundError:
			print("Unable to open file " + filename);
			continue;
			
		#Get the root of this file's XML tree
		root = tree.getroot();

		#Begin building the filtered XML tree
		if (vulnerabilityXMLRoot == None):
			vulnerabilityXMLRoot = copy.deepcopy(root);
			
			#Variables for getting the XML namespaces
			nsRoot = None;
			ns_map = [];
			events = "start", "start-ns";

			#Pull the XML namespaces out and register then with ElementTree
			for event, elem in etree.iterparse(filename, events):
				if (event == "start-ns"):
					ns_map.append(elem);
				elif (event == "start"):
					if (nsRoot == None):
						nsRoot = elem;
					for prefix, uri in ns_map:
						etree.register_namespace(prefix, uri);
					ns_map = [];
			
			#Remove all entries from the new tree
			#CAN MERGE WITH THE FOR LOOP BELOW THIS ONE, AND POTENTIALLY WITH ITERPARSE ABOVE
			for entry in vulnerabilityXMLRoot.findall('entry:entry', namespace):
				vulnerabilityXMLRoot.remove(entry);

		#Iterate through all vulnerability entries in this file's XML tree
		for entry in root.findall('entry:entry', namespace):

			#Keep track of the total number of vulnerabilities seen
			global totalVulnerabilities;
			totalVulnerabilities += 1;

			#Grab the summary section for this vulnerability entry
			cveSummary = entry.find('.//vuln:summary', namespace);
			if (cveSummary != None):
				cveSummary = cveSummary.text;

			#'** REJECT **' indicates this vulnerability entry is invalid and should be ignored
			if (cveSummary != None and "** REJECT **" in cveSummary):
				root.remove(entry);
				continue;

			#The CVE of this vulnerability
			cveID = entry.attrib['id'];

			#The list of vulnerable products this vulnerability affects
			productList = getProducts(entry);
			if (productList == None):
				root.remove(entry);
				continue;

			#Check if this vulnerability affects one of our layers
			affectedLayers = [];
			for product in productList:
				for layer in layers:
					if (layer in product and layer not in affectedLayers):
						affectedLayers.append(layer);
			if (affectedLayers == []):
				root.remove(entry);
				continue;

			#The date this vulnerability was published (YYYY-MM-DD)
			datePublished = entry.find('.//vuln:published-datetime', namespace);

			#Validate the date this vulnerability was published
			if (datePublished == None):
				continue;
			else:
				datePublishedText 	= datePublished.text;
				datePublished 		= datePublishedText.split('T', 1)[0];

			#Generate a random patch date for this vulnerability (will be changed when wehave actual patch dates)
			global patchTime;
			datePatched = generateRandomPatchTime(patchTime, 2, 150);

			#Holds all the information regarding this vulnerability's CVSS score
			cvssObject = getCVSS(entry);
			match = minCVSS.compareCVSS(cvssObject);
			if (not match):
				root.remove(entry);
				continue;

			#The CWE identifier for this vulnerability
			cweID = getCWE(entry);

			#A list of all URL references for this vulnerability
			referenceList = getReferences(entry);

			#Create the vulnerability object
			vulnerability = Vulnerability(cveID, productList, datePublished, datePatched,
										  cvssObject, cweID, referenceList, cveSummary);

			#Store this vulnerability
			for affectedLayer in affectedLayers:
				if (affectedLayer not in vulnerabilityList.keys()):
					vulnerabilityList[affectedLayer] = [];
				vulnerabilityList[affectedLayer].append(vulnerability);
				vulnerabilityXMLRoot.append(entry);

	#Need to duplicate one of the roots, then add relevant vulnerability entries to that new tree
	#-Can't remove bad ones from root b/c root isn't in this scope
	file = "TESTINGOUTPUT.txt";
	sys.stdout = open(file, 'w');
	print(prettify(vulnerabilityXMLRoot));
	sys.stdout = sys.__stdout__;

	return vulnerabilityList;
	


#Gathers the information on the cvss ratings of this vulnerability
#@param entry: the XML object to parse
#returns a CVSS object containing that this entry's vulnerability's CVSS information
def getCVSS(entry):
	cvss = entry.find('.//vuln:cvss', namespace);
	if (cvss == None):
		return None;

	#Gather all CVSS info
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
#@param entry: the XML object to parse
#returns a list of strings that are the references for this entry's vulnerability
def getReferences(entry):
	referenceList = [];
	for reference in entry.findall('.//vuln:references/vuln:reference', namespace):
		referenceURL = reference.attrib['href'];
		referenceList.append(referenceURL);

	return referenceList;



#Locate the CWE ID for this entry
#@param entry: the XML object to parse
#returns a string that is the CWE identifier for this entry's vulnerability
def getCWE(entry):
	cweEntry = entry.find('.//vuln:cwe', namespace);
	if (cweEntry == None):
		return 'None';
	else:
		return cweEntry.attrib['id'];



#Returns the list of products this vulnerability affects
#@param entry: the XML object to parse
#returns a list of strings that are the products for this entry's vulnerability
def getProducts(entry):
	products = [];
	productList = entry.find('.//vuln:vulnerable-software-list', namespace);

	if (productList == None):
		return None;

	for product in productList.findall('.//vuln:product', namespace):
		text = product.text;
		products.append(text);

	return products;



#Search a vulnerability's summary for a string
#@param vulnerabilities: a list of vulnerabilities to search
#@param filter: the filter to apply to each vulnerability's summary
#returns a list of vulnerability objects who's summary contains 'filter'
def filterVulnerabilitiesBySummary(vulnerabilities, filter):
	filteredVulnerabilities = [];

	for vulnerability in vulnerabilities:
		if (vulnerability.summary == None):
			continue;
		if (filter in vulnerability.summary):
			filteredVulnerabilities.append(vulnerability);

	return filteredVulnerabilities;



#Create a plot using MatPlotLib
#@param vulnerabilities: a dictionary, each key is the layer name, each value is the list of vulnearbilities
#@param layers: a list of the names of each layer to be plotted
#returns nothing, simply prints the plot
def createTimeline(vulnerabilities, layers):

	#Initialization of subplots, 1 per layer
	fig, ax = plt.subplots(len(layers) + 1, sharex=True);
	
	#Default start and end dates for the x axis
	startDate = pd.to_datetime("December 31, 2016");
	endDate = pd.to_datetime("January 1, 1999");

	#startDate = pd.to_datetime("January 1, 2010");
	#endDate = pd.to_datetime("December 31, 2016");

	#Create a subplot for each layer
	subplot = 0;
	for layer in layers:
		layerVulnerabilities = vulnerabilities[layer];

		ax[-1].hlines(len(layers) - (subplot), pd.to_datetime("January 1, 1999"), pd.to_datetime("December 31, 2016"), linewidth=3);

		#Format this subplot to look correct
		ax[subplot].spines['right'].set_visible(False)
		ax[subplot].spines['left'].set_visible(False)
		ax[subplot].spines['top'].set_visible(False)
		ax[subplot].xaxis.set_ticks_position('bottom')
		ax[subplot].get_yaxis().set_ticklabels([])
		ax[subplot].set_ylabel(layer.replace(':', ' ').title());
		
		if (layerVulnerabilities == []):
			subplot += 1;
			if (len(layers) == 1):
				startDate, endDate = endDate, startDate;
			continue;

		#Pull the release and patch dates for this vulnerability and plot them
		count = 1;
		filename = layer.replace(':', '_') + ".txt";
		print("Vulnerabilities for " + layer.replace(':', ' ') + " are in " + filename);
		sys.stdout = open(filename, 'w');
		for vulnerability in layerVulnerabilities:
			vulnerability.printVuln();
			#print(vulnerability.cve);

			date = pd.to_datetime(vulnerability.datePublished);
			date2 = date + pd.Timedelta(vulnerability.datePatched, unit='d')
			
			ax[subplot].hlines(count, date, date2);
			ax[-1].hlines(len(layers) - (subplot), date, date2, color='r', linewidth=3);

			#Set our new start/end for the x axis if neccessary
			if (date < startDate):
				startDate = date;
			if (date2 > endDate):
				endDate = date2;
			count += 1;

		sys.stdout = sys.__stdout__;

		ax[subplot].set_ylim([0, count]);
		subplot += 1;
	

	ax[-1].spines['right'].set_visible(False)
	ax[-1].spines['left'].set_visible(False)
	ax[-1].spines['top'].set_visible(False)
	ax[-1].xaxis.set_ticks_position('bottom')
	ax[-1].get_yaxis().set_ticklabels([])
	ax[-1].set_ylim([0, subplot + 1]);
	ax[-1].set_ylabel("Gaps In Layers");

	fig.autofmt_xdate();

	#Set the range of the x axis so everything looks nice
	day = pd.Timedelta("100 days");
	plt.xlim(startDate - day, pd.to_datetime('today'))

	#Label things (title and x axis)
	fig.suptitle("Vulnerabilities in Layered Solutions", fontsize=18);
	plt.xlabel('Dates Vulnerable');
	plt.show();



#Create a timeline with only the dates the vulnerability was published.
def createTimelinePoints(vulnerabilities, layers):
	fig, ax = plt.subplots(figsize=(7,7));

	#Colors to plot
	colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k']

	#Default start and end dates for the x axis
	startDate = pd.to_datetime("December 31, 2016");
	endDate = pd.to_datetime("January 1, 1999");

	#startDate = pd.to_datetime("January 1, 2010");
	#endDate = pd.to_datetime("December 31, 2016");

	colorPointer = 0;

	labels = [];
	handles = [];

	for layer in layers:
		layerVulnerabilities = vulnerabilities[layer];

		count = 1;
		yCount = [];
		layerVulns = [];
		for vulnerability in layerVulnerabilities:
			date = pd.to_datetime(vulnerability.datePublished);
			layerVulns.append(date);

			#Set our new start/end for the x axis if neccessary
			if (date < startDate):
				startDate = date;
			if (date > endDate):
				endDate = date;
			yCount.append(count);
			count += 1;

		label = ax.scatter(layerVulns, yCount, marker='s', color=colors[colorPointer]);
		labels.append(label);
		handles.append(layer.replace(':', ' ').title());

		colorPointer += 1;
		if (colorPointer > 6):
			colorpointer = 0;
		count = 1;

	#Format this subplot to look correct
	ax.spines['right'].set_visible(False)
	ax.spines['left'].set_visible(False)
	ax.spines['top'].set_visible(False)
	ax.xaxis.set_ticks_position('bottom')
	ax.get_yaxis().set_ticklabels([])
	ax.set_ylabel("Vulnerabilities across Layers");

	fig.autofmt_xdate();

	#Set the range of the x axis so everything looks nice
	day = pd.Timedelta("100 days");
	plt.xlim(startDate - day, pd.to_datetime('today'))

	plt.legend(labels, handles, loc='upper left');

	#Label things (title and x axis)
	fig.suptitle("Vulnerabilities in Layered Solutions", fontsize=18);
	plt.xlabel('Dates Vulnerable');
	plt.show();



#Condenses the security gaps (vulnerabilities) into the smallest number possible
#@param vulnerabilities: a dictionary, each key is the layer name, each value is the list of vulnearbilities
#@param layers: a list of the names of each layer to be plotted
#returns a dictionary where they key is the layer name and the value is a 2d list
#-this 2d list is simply a list where each index holds 2 values, the start of the security gap and the end of the security gap
def findSecurityGaps(vulnerabilities, layers):
	#Gaps holds the final gaps for each layer
	gaps = {};
	for layer in layers:

		#layerGaps is used for the gap finding algorithm, then added into the gaps list
		layerGaps = [];
		layerVulnerabilities = vulnerabilities[layer];

		vulnStart = pd.to_datetime(layerVulnerabilities[0].datePublished);
		vulnEnd = vulnStart + pd.Timedelta(layerVulnerabilities[0].datePatched, unit='d');
		layerGaps.append([vulnStart, vulnEnd]);

		#Get the start and end dates of each vulnerability
		for vulnerability in layerVulnerabilities[1:]:
			vulnStart = pd.to_datetime(vulnerability.datePublished);
			vulnEnd = vulnStart + pd.Timedelta(vulnerability.datePatched, unit='d');

			#Fancy insertion into the list so it is sorted from smallest date to largest
			count = 0;
			while (count < len(layerGaps) and vulnStart > layerGaps[count][0]):
				count += 1;

			if (count == len(layerGaps)):
				layerGaps.append([vulnStart, vulnEnd]);
			elif (layerGaps[count][0] == vulnStart):
				if (layerGaps[count][1] > vulnStart):
					layerGaps.insert(count + 1, [vulnStart, vulnEnd]);
				else:
					layerGaps.insert(count, [vulnStart, vulnEnd]);
			else:
				layerGaps.insert(count, [vulnStart, vulnEnd]);

		#Condense the gaps where neccessary
		count = 0;
		while count < (len(layerGaps) - 1):
			#Start dates are equivalent or the first start date is before the second
			if (layerGaps[count][0] == layerGaps[count + 1][0] or (layerGaps[count][0] < layerGaps[count + 1][0] and layerGaps[count + 1][0] < layerGaps[count][1])):
				#But the second end date is after the first
				if (layerGaps[count][1] < layerGaps[count + 1][1]):
					layerGaps[count][1] = layerGaps[count + 1][1];
					del layerGaps[count + 1];
				elif (layerGaps[count][1] > layerGaps[count + 1][1]):
					del layerGaps[count + 1];
				else:
					count += 1;
			else:
				count += 1;

		#Holds all the gaps for each layer
		gaps[layer] = layerGaps;

	return gaps;



#Validate (some of) the options provided on the command line
#@param opt: the option specified on the command line ("--score" or "--auth", etc)
#@param arg: the argument specified with its corresponding option (valid is between 0 and 2)
#returns nothing, exits if error
def checkOptErr(opt, arg):
	if (arg < 0 or arg > 2):
		print();
		print("Invalid --" + opt + " option: " + str(arg));
		print("This option should be 0, 1, or 2");
		print();
		sys.exit(1);



#Generate a random number of days for which this patch was released and applied
#@param patchTime: the time from the release of the patch to when it was applied (default is 7 days)
#@param start: the beginning of the window in which to generate the random
#@param end: the end of the window in which to generate the random
#returns a random integer between start and end offset by patchTime
def generateRandomPatchTime(patchTime, start, end):
	random.seed();
	return (random.randint(start, end) + patchTime);



#Downloads and unzips the NVD files
#Returns nothing.  If files are successfully downloaded and unzipped
# the fileNames global is replaced with those that were downloaded.
def downloadNVDFiles():
	files = [];

	print("Downloading NVD XML Files")
	for url in tqdm(fileURLs):
		r = requests.get(url, stream=True);

		if (not r.ok):
			print("Error downloading file from \'" + url + "\'");
			continue;

		z = zipfile.ZipFile(io.BytesIO(r.content));
		z.extractall();
		
		files.append(z.infolist()[0].filename);

	if (files != []):
		global fileNames;
		fileNames = files;
	print();


#Main method	
#-h: 			print the help string
#--score=?		lowest score that makes a vulnerability relevant
#--av=?: 		lowest level of access vector that makes a vulnerability relevant			
#--ac=?: 		lowest level of access complexity that makes a vulnerability relevant	
#--auth=?: 		lowest level of authentication that makes a vulnerability relevant		
#--conf=?: 		lowest level of confidentiality impact that makes a vulnerability relevant
#--int=?: 		lowest level of integrity impact that makes a vulnerability relevant	
#--avail=?: 	lowest level of availability impact that makes a vulnerability relevant	
#--layers=?:	a comma separated list of the layers we are interested in looking at
#--patchtime=?: the average time it takes from when a patch is released to when it is applied
#--download:	download the latest NVD files from their website
#--input:		a comma separated list of the files to use as input (must be xml with nvd schema)
#--output:		a single filename that specifies the name of the file the filetered xml should be printed to
#Options that begin with "--" should have their argument be a number, either 0 1 or 2
optionsList = "h";
longOptionsList = ["score=", "av=", "ac=", "auth=", 
				   "conf=", "int=", "avail=", "layers=", 
				   "patchtime=", "download", "output=", 
				   "input="];
def main(argv):

	print();
	print(aboutText);
	print();

	#The default values for the "filter" variables
	global minCVSS, patchTime, fileNames, outputFile, layers;
	minScore 			= 0;
	minAccess 			= 0;
	minComplexity 		= 0;
	minAuthentication 	= 0;
	minConfidentiality 	= 0;
	minIntegrity 		= 0;
	minAvailability 	= 0;
	patchTime 			= 7;
	outputFile			= None;


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
			layers = arg.replace(' ', ':');
			layers = layers.lower();
			layers = layers.split(',');
			hasLayer = True;
		elif (opt == "--patchtime"):
			patchTime = int(arg);
			if (patchTime < 0):
				print();
				print("Invalid --patchtime option: " + patchTime);
				print("this option should be a positive number");
				print();
				sys.exit(1);
		elif (opt == "--download"):
			print();
			downloadNVDFiles();
		elif (opt == "--input"):
			inputFiles = arg.split(',');
			for file in inputFiles:
				file = file.lstrip(' ');
				file = file.rstrip(' ');
			fileNames = inputFiles;
		elif (opt == "--output"):
			outputFile = arg.lstrip(' ');
			outputFile = outputFile.rstrip(' ');
			outputFile = arg;

	minCVSS = CVSS(minScore, minAccess, minComplexity, minAuthentication, minConfidentiality, minIntegrity, minAvailability);

	#Ensure we have a set of layers to analyze
	if (hasLayer == False):
		print("Please specify one or more layers to analyze.");
		sys.exit(1);

	#The bulk of this program, the actual gathering of data happens here, and in the parse method
	print();
	print("Analyzing NVD XML Files");
	vulnerabilityList = parse(layers);

	print("Total Vulnerabilities: " + str(totalVulnerabilities));

	createTimeline(vulnerabilityList, layers);
	#createTimelinePoints(vulnerabilityList, layers);


#Ensures this only runs if parse.py is the main file called
if __name__ == "__main__":
	main(sys.argv);
