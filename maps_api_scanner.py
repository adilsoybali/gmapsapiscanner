import requests
import warnings
import json
import sys
import os

def scan_gmaps(apikey):
	vulnerable_apis = []
	url = "https://www.googleapis.com/customsearch/v1?cx=017576662512468239146:omuauf_lfve&q=lectures&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("errors") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Custom Search API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("customsearch 			|| $5 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print "API key is \033[1;31;40m vulnerable \033[0m for Staticmap API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Staticmap 			|| $2 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print "API key is \033[1;31;40m vulnerable \033[0m for Streetview API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Streetview 			|| $7 per 1000 requests")

	url = "https://www.google.com/maps/embed/v1/place?q=Seattle&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print "API key is \033[1;31;40m vulnerable \033[0m for Embed (Basic) API! Here is the PoC HTML code which can be used directly via browser:"
		print "<iframe width=\"600\" height=\"450\" frameborder=\"0\" style=\"border:0\" src=\""+url+"\" allowfullscreen></iframe>"
		vulnerable_apis.append("Embed (Basic)			|| Free")

	url = "https://www.google.com/maps/embed/v1/search?q=record+stores+in+Seattle&key="+apikey
	response = requests.get(url, verify=False)
	if response.status_code == 200:
		print "API key is \033[1;31;40m vulnerable \033[0m for Embed (Advanced) API! Here is the PoC HTML code which can be used directly via browser:"
		print "<iframe width=\"600\" height=\"450\" frameborder=\"0\" style=\"border:0\" src=\""+url+"\" allowfullscreen></iframe>"
		vulnerable_apis.append("Embed (Advanced)		|| Free")

	url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Directions API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Directions 			|| $5 per 1000 requests")
		vulnerable_apis.append("Directions (Advanced) 	|| $10 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Geocode API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Geocode 			|| $5 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Distance Matrix API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Distance Matrix 		|| $5 per 1000 elements")
		vulnerable_apis.append("Distance Matrix (Advanced) 	|| $10 per 1000 elements")

	url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Find Place From Text API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Find Place From Text 		|| $17 per 1000 elements")

	url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Autocomplete API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Autocomplete 			|| $2.83 per 1000 requests")
		vulnerable_apis.append("Autocomplete Per Session 	|| $17 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Elevation API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Elevation 			|| $5 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("errorMessage") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Timezone API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Timezone 			|| $5 per 1000 requests")

	url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Nearest Roads API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Nearest Roads 		|| $10 per 1000 requests")

	url = "https://www.googleapis.com/geolocation/v1/geolocate?key="+apikey
	postdata = {'considerIp': 'true'}
	response = requests.post(url, data=postdata, verify=False)
	if response.text.find("error") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0mfor Geolocation API! Here is the PoC curl command which can be used from terminal:"
		print "curl -i -s -k  -X $'POST' -H $'Host: www.googleapis.com' -H $'Content-Length: 22' --data-binary $'{\"considerIp\": \"true\"}' $'"+url+"'"
		vulnerable_apis.append("Geolocation 			|| $5 per 1000 requests")

	url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Route to Traveled API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Route to Traveled 		|| $10 per 1000 requests")

	url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Speed Limit-Roads API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Speed Limit-Roads 		|| $20 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Place Details API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Place Details 		|| $17 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Nearby Search-Places API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Nearby Search-Places		|| $32 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Text Search-Places API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Text Search-Places 		|| $32 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key="+apikey
	response = requests.get(url, verify=False, allow_redirects=False)
	if response.status_code == 302:
		print "API key is \033[1;31;40m vulnerable \033[0m for Places Photo API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Places Photo 			|| $7 per 1000 requests")

	url = "https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=pizza+near%20par&key="+apikey
	response = requests.get(url, verify=False)
	if response.text.find("error_message") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0m for Query Autocomplete-Places API! Here is the PoC link which can be used directly via browser:"
		print url
		vulnerable_apis.append("Query Autocomplete-Places 	|| $2.83 per 1000 requests")

	url = "https://playablelocations.googleapis.com/v3:samplePlayableLocations?key="+apikey
	postdata = {'area_filter':{'s2_cell_id':7715420662885515264},'criteria':[{'gameObjectType':1,'filter':{'maxLocationCount':4,'includedTypes':['food_and_drink']},'fields_to_return': {'paths': ['name']}},{'gameObjectType':2,'filter':{'maxLocationCount':4},'fields_to_return': {'paths': ['types', 'snapped_point']}}]}
	response = requests.post(url, data=postdata, verify=False)
	if response.text.find("error") < 0:
		print "API key is \033[1;31;40m vulnerable \033[0mfor Playable Locations API! Here is the PoC curl command which can be used from terminal:"
		print "curl -i -s -k  -X $'POST' -H $'Host: playablelocations.googleapis.com' -H $'Content-Length: 302' --data-binary $'{\"area_filter\":{\"s2_cell_id\":7715420662885515264},\"criteria\":[{\"gameObjectType\":1,\"filter\":{\"maxLocationCount\":4,\"includedTypes\":[\"food_and_drink\"]},\"fields_to_return\": {\"paths\": [\"name\"]}},{\"gameObjectType\":2,\"filter\":{\"maxLocationCount\":4},\"fields_to_return\": {\"paths\": [\"types\", \"snapped_point\"]}}]}' $'"+url+"'"
		vulnerable_apis.append("Playable Locations 	|| $10 per 1000 daily active users")

	url = "https://fcm.googleapis.com/fcm/send"
	postdata = "{'registration_ids':['ABC']}"
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json','Authorization':'key='+apikey})
	if response.status_code == 200:
		print "API key is \033[1;31;40m vulnerable \033[0mfor FCM API! Here is the PoC curl command which can be used from terminal:"
		print "curl --header \"Authorization: key="+apikey+"\" --header Content-Type:\"application/json\" https://fcm.googleapis.com/fcm/send -d '{\"registration_ids\":[\"ABC\"]}'"
		vulnerable_apis.append("FCM Takeover 			|| https://abss.me/posts/fcm-takeover/")

	print "-------------------------------------------------------------"
	print "  Results 			|| Cost Table/Reference to Exploit:"
	print "-------------------------------------------------------------"
	for i in range (len(vulnerable_apis)):
	    print "- " + vulnerable_apis[i]
	print "-------------------------------------------------------------"
	return True

warnings.filterwarnings("ignore")
if len(sys.argv) > 1:
	if sys.argv[1] == "--api-key" or sys.argv[1] == "-a":
		if len(sys.argv) > 2:
			scan_gmaps(sys.argv[2])
		else:
			print "Missing api key, aborting."
			print "Either use --api-key as argument such \"python maps_api_scanner.py --api-key KEY\" or directly run script as \"python maps_api_scanner.py\" and supply API key via input."
	elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
		print "Either use --api-key as argument such \"python maps_api_scanner.py --api-key KEY\" or directly run script as \"python maps_api_scanner.py\" and supply API key via input."
	else:
		print "Invalid arguments, aborting."
		print "Either use --api-key as argument such \"python maps_api_scanner.py --api-key KEY\" or directly run script as \"python maps_api_scanner.py\" and supply API key via input."
else:
	apikey = raw_input("Please enter the Google Maps API key you wanted to test: ")
	scan_gmaps(apikey)
