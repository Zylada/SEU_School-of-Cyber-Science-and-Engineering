@load base/frameworks/sumstats
const SCAN_STREAM_404 = "http.hw3.404.scan";
const SCAN_STREAM_ALL  = "http.hw3.all.scan";

global reducer_404: SumStats::Reducer = SumStats::Reducer(
    $stream = SCAN_STREAM_404,
    $apply = set(SumStats::SUM, SumStats::UNIQUE)
);

global reducer_all: SumStats::Reducer = SumStats::Reducer(
    $stream = SCAN_STREAM_ALL,
    $apply = set(SumStats::SUM)
);

event zeek_init()
{
    SumStats::create
   ([
        $name = "http-hw3-404-scanner-detection",
        $epoch = 10min,
        $reducers = set(reducer_404, reducer_all),
        $epoch_result = function(t: time, key: SumStats::Key, result: SumStats::Result) 	{
            local r_404 = result[SCAN_STREAM_404];
            local r_all = result[SCAN_STREAM_ALL];

            local total_404 = r_404$sum;
            local unique_urls = r_404$unique;
            local total_all = r_all$sum;

            if (total_all == 0) return;
            local ratio_404 = total_404 / total_all;

            if (total_404 == 0) return;
            local ratio_unique = unique_urls / total_404;

            if (total_404 > 2 && ratio_404 > 0.2 && ratio_unique > 0.5) 
		{
                print fmt("%s is a scanner with %d 404 scan attempts on %d unique URLs in last 10 minutes",
          key$host, total_404, unique_urls);#如果想输出所有的URL地址该怎么写？
         	}
         }
    ]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    local src_ip = c$id$orig_h;
    local url = c$http$uri;

    SumStats::observe(SCAN_STREAM_ALL,
                      SumStats::Key($host = src_ip),
                      SumStats::Observation($num = 1));

    if (code == 404) {
        SumStats::observe(SCAN_STREAM_404,
                          SumStats::Key($host = src_ip),
                          SumStats::Observation($str = url));
    }
}