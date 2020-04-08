1：注意！注意！注意！
  爬全站视频的代码得到的数据有少许重复，我看了下，软件内部的数据也是重复的
  key：625222f9149e961d
  iv：5efdtf6060e2o330

2：sign的加密方式是md5，看下面原始加密结构：
    params = {
          "page": 页数,
          "special_id": 固定参数
        }
    下面()里面的值是固定的，{}里面的值是params
  （QEBBQADSwrXIXaNqBmMofjfRY/8Sxaxgparams）{}（version25QEBBQADSwrXIXaNqBmMofjfRY/8Sxaxg）
