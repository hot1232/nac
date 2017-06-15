Name: nac-agent
Version: 0.1
Release: 1%{?dist}
Summary: parse nginx log file for network access control
Group: koudai
License: GNU
URL: http://www.com
Source0: nac-agent.tar.gz
BuildRequires: python-inotify
Requires: python-inotify python-redis python-gevent
%description
这个工具完成对nginx日志的分析

%prep
%setup -n %{name}

%build
%install
rm -rf $RPM_BUILD_ROOT
if [ ! -d $RPM_BUILD_ROOT/bin ]
then
mkdir -p $RPM_BUILD_ROOT/bin
fi
if [ ! -d $RPM_BUILD_ROOT/etc/init.d ]
then
mkdir -p $RPM_BUILD_ROOT/etc/init.d 
fi

/usr/bin/install -m 755 nac-agent.py $RPM_BUILD_ROOT/bin/nac-agent
/usr/bin/install -m 755 nac-agent $RPM_BUILD_ROOT/etc/init.d/nac-agent
/usr/bin/install -m 0644 nginx_log_dir.conf $RPM_BUILD_ROOT/etc/nginx_log_dir.conf
%preun
echo "in preun args is: $*"
/sbin/service nac-agent stop
%postun
echo "in postun args is : $*"

if [ "$1" == "0" ]
then
rm -f /bin/nac-agent
rm -f /etc/init.d/nac-agent
fi
%clean
rm -rf $RPM_BUILD_ROOT

%files
/bin/nac-agent
/etc/init.d/nac-agent
/etc/nginx_log_dir.conf
%defattr(-,root,root,-)
%attr(755,root,root) /bin/nac-agent
%attr(755,root,root) /etc/init.d/nac-agent
%doc
 
%changelog
