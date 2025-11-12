<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use DB;
use Auth;
use Carbon\Carbon;
use App\Models\SystemInformation;
use App\Models\SocialLink;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Pagination\Paginator;
use App\Models\Support;
class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
 Paginator::useBootstrapFive();

    
// Add this code block
    Relation::morphMap([
        'offer' => 'App\Models\Offer',
        'service' => 'App\Models\Service',
    ]);
        ///new code start

        view()->composer('*', function ($view)
        {

 $supportInfo = Support::latest()->first();
            view()->share('supportInfo', $supportInfo);
            //global social link code start
//global social link code start
            $socialLinks = SocialLink::all();
            view()->share('socialLinks', $socialLinks);
           
            

            //provider code for frontend

            $frontEndData = DB::table('system_information')->first();

            if ($frontEndData) {

                $front_icon_name = $frontEndData->icon;
                $front_logo_name = $frontEndData->logo;
                 $front_mobile_version_logo = $frontEndData->mobile_version_logo;
                ;
                $front_ins_name = $frontEndData->ins_name;
                $front_ins_url = $frontEndData->main_url;
                $front_ins_add = $frontEndData->address;
                
                $front_ins_email = $frontEndData->email;

                $front_ins_phone = $frontEndData->phone;
                $front_ins_k = $frontEndData->keyword;
                $front_ins_d = $frontEndData->description;

                $front_develop_by = $frontEndData->develop_by;

                // Fetch secondary contact info
                $front_ins_email_one = $frontEndData->email_one;
                $front_ins_phone_one = $frontEndData->phone_one;

            } else {
                // Default values if no data is found
                $front_icon_name = '';
                $front_logo_name = '';
                $front_mobile_version_logo = '';
                $front_ins_name = '';
                $front_ins_add = '';
               $front_ins_url = '';
                $front_ins_email = '';

                $front_ins_phone = '';
                $front_ins_k = '';
                $front_ins_d = '';
                $front_develop_by = '';
                 $front_ins_email_one = '';
                $front_ins_phone_one = '';
            }

              view()->share('front_icon_name', $front_icon_name);
              view()->share('front_ins_url', $front_ins_url);
              view()->share('front_logo_name', $front_logo_name);
              view()->share('front_mobile_version_logo', $front_mobile_version_logo);
              view()->share('front_ins_name', $front_ins_name);
              view()->share('front_ins_add', $front_ins_add);
              view()->share('front_ins_email', $front_ins_email);
              view()->share('front_ins_phone', $front_ins_phone);
              view()->share('front_ins_k', $front_ins_k);
              view()->share('front_ins_d', $front_ins_d);
              view()->share('front_develop_by', $front_develop_by);

                view()->share('front_ins_email_one', $front_ins_email_one);
            view()->share('front_ins_phone_one', $front_ins_phone_one);

            //provider code for frontend end

            if (Auth::check()) {

                //auth check code start


            $data = DB::table('system_information')->where('branch_id',Auth::user()->branch_id)->first();
        if (!$data) {
            $icon_name = '';
            $logo_name ='';
            
            $ins_name = '';
            $ins_add = '';
            $ins_url = '';
            $ins_email = '';

            $ins_phone = '';
            $ins_k = '';
            $ins_d = '';
            $develop_by = '';
            $category_prefix = '';
            $product_prefix = '';

            $tax = '';
            $charge = '';

            view()->share('tax', $tax);
            view()->share('charge', $charge);

      
            view()->share('develop_by', $develop_by);
            view()->share('ins_name', $ins_name);
            view()->share('logo',  $logo_name);
            view()->share('icon', $icon_name);
            view()->share('ins_add', $ins_add);
            view()->share('ins_phone', $ins_phone);
            view()->share('ins_email', $ins_email);

            view()->share('keyword', $ins_k);
            view()->share('description', $ins_d);

        }else{
            view()->share('tax', $data->tax);
            view()->share('charge', $data->charge);
            view()->share('develop_by', $data->develop_by);
            view()->share('ins_name', $data->ins_name);
            view()->share('logo',  $data->logo);
            view()->share('icon', $data->icon);
            view()->share('ins_add', $data->address);
            view()->share('ins_phone', $data->phone);
            view()->share('ins_email', $data->email);

            view()->share('keyword', $data->keyword);
            view()->share('description', $data->description);

        }


                //auth check code end

            }else{

                $icon_name = '';
                $logo_name ='';
                $ins_name = '';
                $ins_add = '';
                $ins_url = '';
                $ins_email = '';

                $ins_phone = '';
                $ins_k = '';
                $ins_d = '';
                $develop_by = '';
              

                $tax = '';
            $charge = '';

            view()->share('tax', $tax);
            view()->share('charge', $charge);

              
                view()->share('develop_by', $develop_by);
                view()->share('ins_name', $ins_name);
                view()->share('logo',  $logo_name);
                view()->share('icon', $icon_name);
                view()->share('ins_add', $ins_add);
                view()->share('ins_phone', $ins_phone);
                view()->share('ins_email', $ins_email);

                view()->share('keyword', $ins_k);
                view()->share('description', $ins_d);


            }
        });


        ///new code end

    }
}
