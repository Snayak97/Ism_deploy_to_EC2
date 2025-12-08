import React from "react";
import Widget from "../../components/charts/widgets/Widget";
import Featured from "../../components/charts/Charts/Featured"
import Chart from "../../components/charts/Charts/Chart"

const ClientAdmin = () => {
  return (
    <div className="flex-1 flex flex-col">
      <div className="flex flex-wrap gap-4 p-4">
        <Widget type="user" />
        <Widget type="order" />
        <Widget type="earning" />
        <Widget type="balance" />
       
      </div>

      <div className="flex flex-col lg:flex-row gap-4 px-4 pb-4">
        <div className="flex-1">
          <Featured/>
        </div>
        <div className="flex-1">
          <Chart title="Last 6 Months (Revenue)" aspect={2.3/1} />
        </div>
      </div>
    </div>
  );
};

export default ClientAdmin;
