#!/bin/sh
# syncing openvas with github

#Origin is the remote origin
ORIGIN=$1
cd /home/jxia/github/openvas_config
git add -A
git commit -m 'automated commit'
echo "just committed"


#if origin not added. Add specified origin
if [$1 = ""]; then
	echo "no origin specified, using default"
else

	if [[ ! $(git remote -v | grep origin ) ]]; then
		 echo "no remote origin yet."
		 git remote add origin $1
	else
		echo "changing remote origin to $1"
	 	git remote set-url origin $1
	fi
fi

 git checkout master
 git push origin
echo "updated branch master"
