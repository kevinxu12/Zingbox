#!/bin/sh



for icsa_id in `cat ids.txt | grep -oh "ICS[AM]*-[0-9]*-[0-9]*-[0-9]*[A-Z]\?" | sort | uniq `

do
   
     echo "\nRetreiving ICSA page for $icsa_id\n"
   
     wget -O ./ICS/$icsa_id.html "https://ics-cert.us-cert.gov/advisories/$icsa_id"
   
     echo "\n\n********** END for $icsa_id ****************\n\n"
  
     sleep 2

done
